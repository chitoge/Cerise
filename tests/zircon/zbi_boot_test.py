#!/usr/bin/env python3
"""Generic ZBI boot-and-assert harness (QEMU-launched OR external serial log).

The pass/fail contract lives in ONE place — `watch_log()` — and is used by both
modes, so a hardware run and the QEMU gate cannot drift apart in what they call
a pass:

  * PASS when every --marker substring AND every --require-regex is present.
  * FAIL on any --forbid substring, any --forbid-regex match, any built-in panic
    pattern, the watched process dying early, or timeout.

Negative assertions are always evaluated before positive ones, so a log that
carries both a pass marker and a panic (or a self-skip) fails.

Two ways to drive it:

  LAUNCH MODE (the `bazel test` gate; unchanged):
      --qemu/--shim/--zbi/--qemu-data-dir
    Boots `qemu -kernel <shim> -initrd <zbi>` on a q35 machine (the proven
    direct-kernel recipe validation/fileserver_grpc_boot_test.py uses for
    netstack3-sized ZBIs), captures the legacy serial port to a file, and polls
    it. QEMU's own liveness (`proc.poll()`) is the "is it still running" signal.

  WATCH MODE (real hardware):
      --no-launch --serial-log=PATH
    Nothing is spawned. PATH is a log some OTHER process is appending to —
    e.g. `amtterm` capturing AMT Serial-over-LAN from the CF-SZ5 laptop. An
    optional --alive-command supplies liveness (non-zero exit => the capture
    died); without it the run simply proceeds until the contract is met or the
    timeout expires.

    Watching someone else's file adds ways to report a pass that the QEMU path
    does not have, all of them guarded: markers left over from a PREVIOUS run
    (rejected at startup unless --allow-prefilled-log), the log being truncated
    or rotated so a failure line disappears (the log must stay append-only under
    one inode), and a failure flushed just after the success marker
    (--settle-seconds re-checks after a hold).

Used by tests/zircon for the on-target Zircon kernel-unit-test boot gate, but
deliberately product-agnostic so other ZBI boot tests can reuse it.
See tests/zircon/cf_sz5_utest_contract.sh for the hardware contract built on it.
"""
from __future__ import annotations
import argparse, os, pathlib, re, shutil, subprocess, sys, time

PANIC_PATTERNS = ("KERNEL PANIC", "ZIRCON KERNEL PANIC", "triple fault", "KERNEL FAULT")


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def snapshot_log(path: pathlib.Path):
    """One consistent look at the log: ((device, inode), text), or (None, None).

    Identity and contents come from a SINGLE open descriptor, so the bytes
    checked are provably the bytes of the file whose identity was recorded — a
    separate stat() then read() could straddle a rotation and attribute one
    file's contents to another file's inode.

    Decoded latin-1, which is byte-preserving and cannot raise: a real UART emits
    line noise and half-written multi-byte sequences, and every marker this
    harness matches is ASCII. A lossy UTF-8 decode would substitute U+FFFD for
    those bytes; latin-1 leaves the ASCII around them exactly where it was, so
    noise can never swallow part of a FORBIDDEN phrase and turn a failing run
    into a passing one.
    """
    try:
        fd = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        return None, None
    try:
        st = os.fstat(fd)
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return (st.st_dev, st.st_ino), b"".join(chunks).decode("latin-1")
    finally:
        os.close(fd)


def read_log(path: pathlib.Path, default=""):
    """The watched log's contents, or `default` while the writer has not created
    it — which is how "not there yet" is told apart from "there and empty"."""
    _, txt = snapshot_log(path)
    return default if txt is None else txt


# A debuglog record boundary can fall MID-WORD. The kernel emits its own
# "[ts] pid:tid> " prefix at the start of every record, so a marker longer than
# the remaining space in a record arrives split, e.g. this real CF-SZ5 capture:
#
#   [00000.410] 00000:01063>   ...traps an I/O write : guest-entry OK: ...a 64-b
#   [00000.414] 00000:01063> it guest; I/O exit port=0x10 value=0x42
#
# "64-bit guest" became "64-b" + newline + prefix + "it guest". A contract that
# matched only the raw text therefore FAILED on hardware while the marker was
# plainly present — the harness, not the run, was wrong.
# The \r? is load-bearing: a real SOL capture arrives CRLF-terminated, so
# stripping only from "\n" leaves the carriage return sitting inside the rejoined
# word ("64-b\rit guest") and the marker still does not match.
_DEBUGLOG_PREFIX = re.compile(r"\r?\n\[\d+\.\d+\] \d+:\d+> ")


def rejoin_debuglog(txt):
    """Undo debuglog record splitting so a split marker still matches.

    Deliberate trade-off: this also concatenates genuinely adjacent records,
    including ones from different threads, so in principle a marker could be
    formed by splicing unrelated output. For the long, distinctive strings these
    contracts assert that is not a realistic collision, and the alternative —
    markers that silently fail to match on real hardware — is the far worse
    failure, because it reads as a broken run rather than a broken matcher.
    """
    return _DEBUGLOG_PREFIX.sub("", txt)


def log_variants(txt):
    """Every form a marker could legitimately have taken in the log.

    Two independent splitters can cut a line:

    1. The KERNEL's debuglog cuts at a record boundary and prefixes the next
       record with "[ts] pid:tid> " -- handled by `rejoin_debuglog`.
    2. The VMM's own `sayln` splits a message over SAY_CHUNK and prefixes each
       continuation with "+ ".

    (2) is ambiguous to undo, and that is why both forms are produced rather
    than one being guessed at. `sayln` prefers to break on a space and then
    trims the head, so the space is GONE: rejoining "foo" + "bar" must yield
    "foo bar". But when no space is available it breaks mid-token, and then the
    same rejoin must yield "foobar". Nothing in the log distinguishes the two
    cases, so both are offered.

    Positive assertions may match ANY variant; negative assertions are checked
    against ALL of them, which is strictly stricter than checking the raw text.
    """
    joined = rejoin_debuglog(txt)
    return (txt, joined, joined.replace("+ ", ""), joined.replace("+ ", " "))


def check_forbidden(txt, forbid, forbid_regexes):
    """Return a failure message if `txt` violates a negative assertion, else None.

    Negative assertions are checked BEFORE the positive ones so that a log which
    contains both a pass marker and a panic (or a self-skip) fails.
    """
    vs = log_variants(txt)
    for bad in list(forbid) + list(PANIC_PATTERNS):
        if any(bad in v for v in vs):
            return f"forbidden marker {bad!r} in serial:\n{txt[-800:]}"
    for rx in forbid_regexes:
        hits = next((h for h in (rx.findall(v) for v in vs) if h), [])
        if hits:
            return (f"forbidden pattern /{rx.pattern}/ appears {len(hits)} time(s) "
                    f"in serial (expected 0):\n{txt[-800:]}")
    return None


def satisfied(txt, markers, regexes):
    """True when every positive assertion holds, in the raw log OR the rejoined one.

    Checked against both because the debuglog can split a marker across records
    (see rejoin_debuglog). Matching either form is a deliberate loosening of the
    POSITIVE assertions only; the negative ones are checked against both forms,
    which is strictly stricter.
    """
    vs = log_variants(txt)
    return (all(any(m in v for v in vs) for m in markers)
            and all(any(rx.search(v) for v in vs) for rx in regexes))


def watch_log(serial, *, markers, regexes, forbid=(), forbid_regexes=(),
              timeout_seconds=240.0, is_alive=None, dead_label="the boot",
              poll_seconds=2.0, settle_seconds=0.0, tag="zbi-boot"):
    """Poll a growing log until the contract is met; raise AssertionError otherwise.

    `serial` is a pathlib.Path that someone else (QEMU, or amtterm) is writing.
    `is_alive`, when given, is a zero-arg callable returning False once the thing
    producing the log has exited; a dead producer ends the wait early after ONE
    final re-read (the markers may have been written just before it exited).
    `dead_label` may be a callable, so an exit code can be formatted lazily.
    `settle_seconds`, when non-zero, holds after the contract is first met and
    re-checks the negative assertions, so a panic flushed a moment after the
    success marker still fails the run.
    Returns the final log text on success.

    The log is only ever appended to, so every read must have the previous read
    as a PREFIX and the file must keep its inode. If either breaks, something
    truncated, rewrote or rotated it, and any forbidden line it used to carry is
    now invisible — the one way a growing-log watcher can turn a failing run into
    a passing one, so it is a hard failure. The prefix test matters more than a
    size test: a truncate-and-regrow between two polls leaves the size unchanged
    or larger and would slip past a size comparison entirely.
    """
    def label():
        return dead_label() if callable(dead_label) else dead_label

    def check_same_file(now):
        if seen is None:
            return
        if now is None:
            # It existed a moment ago and does not now. Whatever it said last is
            # only in this process's memory, and cannot be re-checked against the
            # negative assertions — so it can no longer be trusted to pass.
            raise AssertionError(
                f"{serial} disappeared while being watched; the log it carried can no "
                "longer be verified, so this run proves nothing")
        if seen != now:
            raise AssertionError(
                f"{serial} was replaced (dev/inode changed) while being watched; a rotated "
                "log may have carried away a failure, so this run proves nothing")

    def check_append_only(new_txt):
        if not new_txt.startswith(txt):
            raise AssertionError(
                f"{serial} is not append-only: {len(txt)} bytes previously read are no "
                f"longer its prefix ({len(new_txt)} bytes now). It was truncated or "
                "rewritten, so any earlier failure line is now invisible and this run "
                "proves nothing")

    def refresh():
        """Re-read the log, enforcing the integrity invariants, then the
        forbidden patterns. Negative assertions are always checked BEFORE the
        positive ones, so a log carrying both a pass marker and a panic fails."""
        nonlocal txt, seen
        now, new_txt = snapshot_log(serial)
        check_same_file(now)
        if now is None:            # never existed yet; nothing to check
            return
        seen = now
        check_append_only(new_txt)
        txt = new_txt
        bad = check_forbidden(txt, forbid, forbid_regexes)
        if bad:
            raise AssertionError(bad)

    def report_pass(txt, why):
        for rx in regexes:
            # Search the rejoined text too, and in the SAME order satisfied()
            # does: a regex that only matches across a debuglog record split
            # returns None here, and reporting the pass must not crash on it.
            m = next((mm for mm in (rx.search(v) for v in log_variants(txt)) if mm), None)
            shown = m.group(0) if m else "<matched across a debuglog record split>"
            print(f"[{tag}] matched /{rx.pattern}/ -> {shown!r}", flush=True)
        print(f"[{tag}] PASS: {why}", flush=True)

    txt = ""
    seen = None
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        refresh()
        if satisfied(txt, markers, regexes):
            if settle_seconds > 0:
                # The contract is met, but the producer may not have flushed
                # everything: a panic AFTER the success marker must still fail.
                print(f"[{tag}] contract met; settling {settle_seconds}s before "
                      "accepting it", flush=True)
                time.sleep(settle_seconds)
                refresh()
            report_pass(txt, "all required markers/regexes observed")
            return txt
        if is_alive is not None and not is_alive():
            # The producer exited (e.g. Zircon rebooted after the boot-test
            # script and -no-reboot fired). Re-read the now-final log and
            # re-check — including the forbidden patterns — before failing.
            refresh()
            if satisfied(txt, markers, regexes):
                report_pass(txt, f"markers present in final serial "
                                 f"({label()} ended after the boot-test)")
                return txt
            # Name WHICH assertions failed. "ended before all markers seen" with
            # no list forces the reader to re-derive the contract by hand, and
            # this is the path a finished capture always takes.
            vs = log_variants(txt)
            missing_m = [m for m in markers if not any(m in v for v in vs)]
            missing_r = [rx.pattern for rx in regexes
                         if not any(rx.search(v) for v in vs)]
            raise AssertionError(
                f"{label()} ended before all markers seen; "
                f"missing markers={missing_m} regexes={missing_r}"
                f"\n--- serial tail ---\n{txt[-800:]}")
        time.sleep(poll_seconds)
    # Deliberately NO final re-read here: a timeout stays a timeout. Re-reading
    # would make the harness leniently accept markers that landed after we gave
    # up, and the only permitted drift in this contract is towards strictness.
    missing_m = [m for m in markers if m not in txt]
    missing_r = [rx.pattern for rx in regexes if not rx.search(txt)]
    raise AssertionError(
        f"timed out after {timeout_seconds}s; missing markers={missing_m} "
        f"regexes={missing_r}\n--- serial tail ---\n{txt[-1500:]}")


def _alive_command_probe(command, probe_timeout=10.0):
    """Liveness probe from a shell command; non-zero exit means 'the writer died'.

    The probe is itself bounded: a command that hangs would otherwise pin the
    poll loop and defeat --timeout-seconds entirely. A hung probe is treated as
    'unknown, keep waiting' so the overall deadline is what ends the run.
    """
    def probe():
        try:
            return subprocess.run(command, shell=True, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,
                                  timeout=probe_timeout).returncode == 0
        except subprocess.TimeoutExpired:
            print(f"[zbi-boot] --alive-command timed out after {probe_timeout}s; "
                  "treating liveness as unknown", flush=True)
            return True
    return probe


def main():
    ap = argparse.ArgumentParser()
    # Launch-mode inputs. Required unless --no-launch is passed.
    ap.add_argument("--qemu")
    ap.add_argument("--shim")
    ap.add_argument("--zbi")
    ap.add_argument("--qemu-data-dir")
    ap.add_argument("--no-launch", action="store_true",
                    help="Do not spawn QEMU; watch an externally-written --serial-log "
                         "(e.g. amtterm capturing AMT Serial-over-LAN from real hardware).")
    ap.add_argument("--serial-log",
                    help="Log file to watch. REQUIRED with --no-launch, and rejected without "
                         "it: launch mode DELETES this file before booting, and that must "
                         "never be pointed at an arbitrary path, so launching always uses "
                         "$TEST_TMPDIR/zbi-boot-serial.log.")
    ap.add_argument("--alive-command",
                    help="With --no-launch: shell command re-run each poll; a non-zero exit "
                         "means the log's writer died and the run fails immediately. "
                         "Omitted means 'assume alive until the timeout'.")
    ap.add_argument("--allow-prefilled-log", action="store_true",
                    help="With --no-launch: skip the startup staleness guard. By default the "
                         "run fails if ANY required marker or regex is already present in "
                         "--serial-log before watching begins, because a marker that predates "
                         "the run cannot be attributed to it — leftovers from a previous boot "
                         "would be credited to this one. Use a fresh log path per run.")
    ap.add_argument("--marker", action="append", default=[],
                    help="Required substring (repeatable).")
    ap.add_argument("--require-regex", action="append", default=[],
                    help="Required regex, searched over the whole serial log (repeatable).")
    ap.add_argument("--forbid", action="append", default=[],
                    help="Forbidden substring; its appearance fails the test (repeatable).")
    ap.add_argument("--forbid-regex", action="append", default=[],
                    help="Forbidden regex; the run fails unless it matches ZERO times "
                         "(repeatable). Use for assertions a substring cannot express, and "
                         "for 'the thing under test did not silently skip itself' — e.g. "
                         "--forbid-regex='VMX not supported here', which a self-skipping "
                         "hypervisor suite prints while still reporting a green summary.")
    ap.add_argument("--timeout-seconds", type=float, default=240.0)
    ap.add_argument("--poll-seconds", type=float, default=2.0)
    ap.add_argument("--static-log", action="store_true",
                    help="With --no-launch: the log is already COMPLETE (an archived "
                         "capture). Evaluate it once and exit with a verdict instead of "
                         "watching for growth. Without this, checking a finished capture "
                         "that does not satisfy the contract tails until --timeout-seconds "
                         "even though nothing can ever append to it. Implies "
                         "--allow-prefilled-log, since a complete log is prefilled by "
                         "definition; the staleness guard is meaningless when the run being "
                         "judged is explicitly a past one.")
    ap.add_argument("--settle-seconds", type=float, default=0.0,
                    help="After the contract is first satisfied, wait this long, re-read the "
                         "log and re-check the FORBIDDEN patterns before accepting the pass. "
                         "Guards against a panic (or any failure line) that the writer "
                         "flushes a moment after the success marker. Default 0 keeps the "
                         "existing gates' behaviour exactly; real hardware wants a few "
                         "seconds, since a UART capture lags the machine.")
    ap.add_argument("--memory-mb", type=int, default=2048)
    # QEMU machine and CPU. Defaults keep the portable TCG recipe (works
    # anywhere, no VT-x); on a host with hardware virtualization pass
    # --machine=q35,accel=kvm --cpu=host to expose (nested) VT-x so the in-kernel
    # hypervisor tests actually run instead of self-skipping.
    ap.add_argument("--machine", default="q35")
    # Guest CPU count. Default 1 so every existing caller boots exactly as
    # before; pass more when the thing under test needs the *kernel* to have
    # more than one CPU to schedule on — e.g. an SMP VMM, where two VP threads
    # time-sliced on one CPU would demonstrate interleaving but not parallelism.
    ap.add_argument("--smp", type=int, default=1)
    ap.add_argument("--cpu", default="qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx")
    # Block devices. Attached as NVMe, matching the single-disk recipe the fshost
    # gate uses (validation/fshost_boot_test.py) so that one disk means exactly
    # one fuchsia.hardware.block.volume.Service instance and a consumer that has
    # to CHOOSE is being tested on purpose rather than by accident.
    #
    # Two forms, and the difference is provenance rather than convenience:
    #   --disk names an image the caller built (a GPT, an ESP, a decoy partition);
    #   --blank-disk-mb creates a FRESH zero-filled image in $TEST_TMPDIR per run,
    #   so a test whose claim is "these bytes were written by this boot" cannot
    #   have a previous run's content credited to it.
    # Both are repeatable and the order is the order QEMU sees them, which is what
    # a multi-disk selection test needs.
    #
    # PASS --memory-mb=4096 WHEN YOU ATTACH A DISK. Measured, not guessed: with an
    # NVMe device attached and the 2048 MB default, QEMU exits with status **0**
    # immediately after SeaBIOS prints "Booting from ROM.." and the kernel never
    # emits a single line. The same ZBI boots fine at 2048 MB with no disk, and
    # fine at 4096 MB with one. The symptom is the problem: a clean exit and an
    # empty serial log read as a hang, a bad image or a broken harness, and
    # nothing about it points at memory. The fshost gate
    # (validation/fshost_boot_test.py) already boots its single-NVMe machine at
    # 4096 MB.
    ap.add_argument("--disk", action="append", default=[], metavar="PATH",
                    help="Attach this raw image as an NVMe disk (repeatable).")
    ap.add_argument("--blank-disk-mb", action="append", default=[], type=int,
                    metavar="MB",
                    help="Create a fresh blank raw image of this size in $TEST_TMPDIR "
                         "and attach it as an NVMe disk (repeatable).")
    ns = ap.parse_args()

    if not ns.marker and not ns.require_regex:
        raise SystemExit("at least one --marker or --require-regex is required")
    regexes = [re.compile(r) for r in ns.require_regex]
    forbid_regexes = [re.compile(r) for r in ns.forbid_regex]

    if ns.no_launch:
        if not ns.serial_log:
            raise SystemExit("--no-launch requires --serial-log=PATH")
        for flag, value in (("--qemu", ns.qemu), ("--shim", ns.shim), ("--zbi", ns.zbi),
                            ("--qemu-data-dir", ns.qemu_data_dir),
                            # Nothing is launched, so nothing can be given a disk.
                            # Silently ignoring these would let a contract that
                            # DEPENDS on a disk pass while watching a log produced
                            # by a machine that never had one.
                            ("--disk", ns.disk), ("--blank-disk-mb", ns.blank_disk_mb)):
            if value:
                raise SystemExit(f"{flag} is meaningless with --no-launch")
        serial = pathlib.Path(ns.serial_log)
        # Staleness guard: crediting a PREVIOUS run's output to this one is the
        # one way this mode can report success while the hardware did nothing.
        # Rejecting only a fully-satisfying prefill is not enough — a stale
        # marker A plus a fresh marker B would still pass — so ANY required
        # marker present before we started watching is fatal.
        if ns.static_log:
            # A finished capture has no producer, so "keep waiting" can never
            # change the answer. Reject the flags that only mean something for a
            # live one rather than silently ignoring them.
            for flag, value in (("--alive-command", ns.alive_command),
                                ("--settle-seconds", ns.settle_seconds)):
                if value:
                    raise SystemExit(f"{flag} is meaningless with --static-log")
            if not serial.exists():
                raise SystemExit(f"--static-log: {serial} does not exist")
        if not ns.allow_prefilled_log and not ns.static_log:
            pre = read_log(serial)
            stale = [m for m in ns.marker if m in pre] + \
                    [rx.pattern for rx in regexes if rx.search(pre)]
            if stale:
                raise SystemExit(
                    f"{serial} already contains required marker(s) {stale} before the run "
                    "started; they cannot be attributed to this run and would be credited "
                    "to it. Point --serial-log at a fresh file per run "
                    "(or pass --allow-prefilled-log).")
        if ns.static_log:
            # Reuse the live path rather than adding a second notion of "passes":
            # a producer that is already dead makes the loop do exactly one read,
            # check the forbidden patterns first as always, and then render a
            # verdict. Same contract, one implementation.
            is_alive = lambda: False
            dead_label = "the archived capture"
        else:
            is_alive = _alive_command_probe(ns.alive_command) if ns.alive_command else None
            dead_label = "the serial capture"
        print(f"[zbi-boot] {'evaluating' if ns.static_log else 'watching'} {serial} "
              f"(nothing launched); "
              f"markers={ns.marker} regexes={ns.require_regex} "
              f"forbid={ns.forbid} forbid_regex={ns.forbid_regex}", flush=True)
        try:
            watch_log(serial, markers=ns.marker, regexes=regexes, forbid=ns.forbid,
                      forbid_regexes=forbid_regexes, timeout_seconds=ns.timeout_seconds,
                      is_alive=is_alive, dead_label=dead_label,
                      poll_seconds=ns.poll_seconds, settle_seconds=ns.settle_seconds)
        except AssertionError as exc:
            print(f"[zbi-boot] FAIL: {exc}", file=sys.stderr, flush=True)
            return 1
        return 0

    for flag, value in (("--alive-command", ns.alive_command),
                        ("--serial-log", ns.serial_log),
                        ("--allow-prefilled-log", ns.allow_prefilled_log)):
        if value:
            raise SystemExit(f"{flag} requires --no-launch")
    qemu = _need(ns.qemu, "qemu")
    shim = _need(ns.shim, "shim")
    zbi = _need(ns.zbi, "zbi")
    datadir = _need(ns.qemu_data_dir, "qemu data dir")

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    serial = tmp / "zbi-boot-serial.log"
    if serial.exists():
        serial.unlink()

    cmd = [qemu, "-L", datadir, "-machine", ns.machine, "-nographic", "-monitor", "none",
           "-no-reboot", "-m", f"{ns.memory_mb}M",
           "-cpu", ns.cpu, "-smp", str(ns.smp),
           "-serial", f"file:{serial}",
           "-kernel", shim, "-initrd", zbi]

    # Disks, in the order given: caller-supplied images first, then the blank ones
    # this run creates. A blank image is (re)created every run — never reused —
    # because the whole reason to ask for one is that the test's claim is about
    # bytes THIS boot wrote.
    disks = []
    for i, path in enumerate(ns.disk):
        # COPIED into $TEST_TMPDIR, never attached in place, for two reasons that
        # both bite. A caller-supplied image is a build artifact and therefore
        # read-only, and QEMU opens a -drive read-write by default, so attaching
        # it directly fails to open — which surfaces as an immediate exit and an
        # empty serial log, i.e. as something that looks nothing like its cause.
        # And if it were writable, a boot that wrote to it would silently change
        # what every later run of every test using that image sees. Same
        # provenance rule the blank form follows: what this boot sees is a fresh
        # copy of what the caller built.
        img = tmp / f"zbi-boot-disk-{i}.img"
        if img.exists():
            img.unlink()
        shutil.copyfile(path, img)
        os.chmod(img, 0o600)
        disks.append(str(img))
    for i, mb in enumerate(ns.blank_disk_mb):
        img = tmp / f"zbi-boot-blank-{i}.img"
        if img.exists():
            img.unlink()
        with open(img, "wb") as f:
            f.truncate(mb * 1024 * 1024)
        disks.append(str(img))
    for i, path in enumerate(disks):
        cmd += ["-drive", f"file={path},if=none,format=raw,id=zbidisk{i}",
                "-device", f"nvme,drive=zbidisk{i},serial=cerisedisk{i}"]

    print(f"[zbi-boot] booting {os.path.basename(zbi)}; "
          f"disks={disks}; "
          f"markers={ns.marker} regexes={ns.require_regex}", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        watch_log(serial, markers=ns.marker, regexes=regexes, forbid=ns.forbid,
                  forbid_regexes=forbid_regexes, timeout_seconds=ns.timeout_seconds,
                  is_alive=lambda: proc.poll() is None,
                  dead_label=lambda: f"QEMU (exited code {proc.returncode})",
                  poll_seconds=ns.poll_seconds, settle_seconds=ns.settle_seconds)
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
