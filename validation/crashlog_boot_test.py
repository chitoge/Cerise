#!/usr/bin/env python3
"""Cerise post-mortem gate: kernel crashlog survives a warm reboot.

Boots //products:x64-crashlog via the direct-kernel path in ONE QEMU session,
run WITHOUT -no-reboot so a guest-initiated reset warm-reboots the same kernel
image (RAM persists across QEMU system_reset). The product carries a
ZBI_TYPE_NVRAM region (so the PC platform binds MappedCrashlog/ram-crashlog) and
the boot option kernel.cerise-test-crashlog=true, which drives the
self-terminating recovery-gated hook in
zircon/kernel/platform/pc/platform.cc (cerise_crashlog_test_hook):

  boot 1 (cold): no recovered crashlog -> emit CERISE-CRASHLOG-TRIGGER and
                 panic(). panic() stows a crashlog to the NVRAM ram-crashlog
                 region (SW reason KERNEL PANIC + the intentional-panic message
                 in the payload) and, halt_on_panic=false, reboot()s the machine.
  boot 2 (warm): MappedCrashlog recovers the stowed crashlog; the hook prints it
                 to serial bracketed by CERISE-CRASHLOG markers and boot proceeds
                 normally (NO second panic).

The gate asserts, IN ORDER: the boot-1 trigger, the boot-2 recovered-crashlog
markers, and that the recovered payload carries the KERNEL PANIC reason AND the
exact intentional-panic message (proving the crashlog content — not just a flag —
survived the reboot). It also asserts EXACTLY ONE trigger fired: a second trigger
would mean recovery failed and the machine is in a panic->reboot boot loop.
"""
from __future__ import annotations
import argparse, os, pathlib, subprocess, sys, time

# boot 1: the cold-boot hook forces an intentional panic. panic()'s own output
# reaches serial reliably (an ordinary printf just before it would be lost to the
# panic-interrupted debuglog drain), so the LIVE PANIC BANNER is the cold-boot
# signal. It appears exactly once: recovered payloads render the reason as
# "ZIRCON REBOOT REASON (KERNEL PANIC)", never re-echoing this banner — so its
# count is a precise boot-loop guard.
PANIC_BANNER = "ZIRCON KERNEL PANIC"
# the intentional panic message (live on boot 1 AND in boot 2's recovered payload).
PANIC_MSG = "cerise-test-crashlog: intentional panic"
# boot 2: the recovered-crashlog markers + the recovered SW reason.
RECOVERED_BEGIN = "CERISE-CRASHLOG: recovered previous-boot crashlog"
RECOVERED_REASON = "ZIRCON REBOOT REASON (KERNEL PANIC)"
RECOVERED_END = "CERISE-CRASHLOG: end of recovered crashlog"

# The full ordered chain, earliest-to-latest, a working warm-reboot crashlog
# recovery must produce on serial. Marker 5 (PANIC_MSG) is matched AFTER the
# recovered-reason position, so it asserts the panic message was recovered FROM
# RAM into boot 2's payload — not merely re-read from boot 1's live output.
ORDERED_MARKERS = [
    PANIC_BANNER,      # boot 1: the live intentional panic
    RECOVERED_BEGIN,   # boot 2: recovered crashlog surfaced
    RECOVERED_REASON,  # boot 2: the recovered SW reason is KERNEL PANIC
    PANIC_MSG,         # boot 2: the panic message, recovered from RAM
    RECOVERED_END,     # boot 2: clean end of the recovered crashlog
]

PANIC_TIMEOUT_S = 300.0      # boot 1 -> cold-boot panic (near-immediate)
RECOVER_TIMEOUT_S = 420.0    # panic -> warm reboot -> boot 2 recovery


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def _read(serial: pathlib.Path) -> str:
    return serial.read_text(errors="replace") if serial.exists() else ""


def _wait_for(serial, needle, timeout_s, proc):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        txt = _read(serial)
        if needle in txt:
            return txt
        # A guest panic->reboot does NOT exit QEMU (no -no-reboot: reset re-runs
        # the kernel), so proc staying alive is expected. A dead proc means QEMU
        # itself died (or a reset with -no-reboot slipped in) -> fail loudly.
        if proc.poll() is not None:
            raise AssertionError(
                f"QEMU exited (rc={proc.returncode}) before {needle!r} appeared "
                f"(a warm reboot should re-run the kernel, not exit)")
        time.sleep(2)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {needle!r}")


def _assert_ordered(txt: str, markers):
    last = -1
    for m in markers:
        i = txt.find(m, last + 1)
        if i < 0:
            raise AssertionError(f"missing expected chain marker {m!r} on serial")
        if i <= last:
            raise AssertionError(f"chain marker {m!r} out of order on serial")
        last = i


def _symbolize(symbolize, store, llvm_symbolizer, serial: pathlib.Path) -> str:
    """Pipe the serial log through //src/cerise/tools/symbolize against the kernel
    .build-id store, returning the symbolized text (or "" on any failure — never
    let symbolization mask the real result)."""
    if not (symbolize and store and llvm_symbolizer and serial.exists()):
        return ""
    try:
        env = dict(os.environ, CERISE_LLVM_SYMBOLIZER=llvm_symbolizer)
        out = subprocess.run(
            [symbolize, "--build-id-dir", store, "--llvm-symbolizer", llvm_symbolizer, str(serial)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, env=env, check=False,
        )
        return out.stdout if out.returncode == 0 else ""
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--shim", required=True)
    ap.add_argument("--zbi", required=True)
    ap.add_argument("--qemu-data-dir", required=True)
    # (debugging, D4): the recovered crashlog is kernel frames as
    # raw symbolizer markup ({{{bt}}}/{{{module}}}/{{{mmap}}}); wire the symbolize
    # tool + the kernel .build-id store so both the recovered crashlog (on success)
    # and any failing serial tail print NAMED frames, not hex — the symbolization
    # pipeline applied to the post-mortem gate.
    ap.add_argument("--symbolize", default="")
    ap.add_argument("--build-id-dir", default="")
    ap.add_argument("--llvm-symbolizer", default="")
    ns = ap.parse_args()
    qemu = _need(ns.qemu, "qemu")
    shim = _need(ns.shim, "shim")
    zbi = _need(ns.zbi, "zbi")
    datadir = _need(ns.qemu_data_dir, "qemu data dir")

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    outdir = pathlib.Path(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR", str(tmp)))
    outdir.mkdir(parents=True, exist_ok=True)
    serial = outdir / "crashlog-serial.log"
    if serial.exists():
        serial.unlink()

    # NOTE: NO -no-reboot. A guest reset (panic -> reboot()) becomes a QEMU
    # system_reset that re-runs -kernel/-initrd; QEMU DRAM survives the reset, so
    # the NVRAM ram-crashlog region (at 0x40000000, the middle of this 2 GiB
    # guest — clear of both the low kernel and the high ZBI reload) persists.
    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-m", "2048M",
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-kernel", shim, "-initrd", zbi]
    print("[crashlog] booting x64-crashlog (direct-kernel, warm-reboot allowed)", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        _wait_for(serial, PANIC_BANNER, PANIC_TIMEOUT_S, proc)
        print("[crashlog] cold boot panicked as designed; awaiting warm reboot + recovery",
              flush=True)

        # The first recovered-crashlog block is boot 2 (recovering boot 1's panic);
        # wait for its clean end, then assert on boots 1+2. (After userboot's smoke
        # program exits the guest clean-reboots repeatedly; we stop as soon as the
        # panic recovery is proven, so only ~2 boots run.)
        _wait_for(serial, RECOVERED_END, RECOVER_TIMEOUT_S, proc)
        txt = _read(serial)

        # Exactly one LIVE panic: a second "ZIRCON KERNEL PANIC" means boot 2 failed
        # to recover, cold-booted, and re-panicked (a panic/reboot loop). Recovered
        # payloads render the reason as "ZIRCON REBOOT REASON (KERNEL PANIC)" and
        # never re-emit this banner, so its count is unambiguous.
        n_panics = txt.count(PANIC_BANNER)
        if n_panics != 1:
            raise AssertionError(
                f"expected exactly one live {PANIC_BANNER!r} (one panic), saw {n_panics} — "
                f"crashlog recovery failed and the guest is in a panic/reboot loop")

        _assert_ordered(txt, ORDERED_MARKERS)
        print("[crashlog] PASS: panic stowed a crashlog to ram-crashlog, warm reboot "
              "preserved it, and boot 2 recovered+printed it (KERNEL PANIC reason and "
              "the intentional-panic message survived across the reboot)", flush=True)
        # Surface the recovered crashlog SYMBOLIZED: the stowed payload carries kernel
        # symbolizer markup, so the symbolization pipeline resolves its {{{bt}}} to named frames.
        sym = _symbolize(ns.symbolize, ns.build_id_dir, ns.llvm_symbolizer, serial)
        if sym:
            tail = "\n".join(sym.splitlines()[-40:])
            print("[crashlog] recovered crashlog (symbolized tail):\n" + tail, flush=True)
    except AssertionError:
        # D4: on failure, end with the symbolized serial tail, not raw hex markup.
        sym = _symbolize(ns.symbolize, ns.build_id_dir, ns.llvm_symbolizer, serial)
        if sym:
            tail = "\n".join(sym.splitlines()[-60:])
            print("[crashlog] FAILURE — symbolized serial tail:\n" + tail,
                  file=sys.stderr, flush=True)
        raise
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
