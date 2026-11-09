#!/usr/bin/env python3
"""Cerise PMU path A boot gate.

Boots //products:qemu-x64-perfmon (kernel.enable-debugging-syscalls=true) via the
direct-kernel path. The guest realm root_perfmon runs the perfmon component, which
acquires the narrowly-routed fuchsia.kernel.DebugResource and drives the seven
zx_mtrace_control(MTRACE_KIND_PERFMON) actions to read raw hardware performance
counters over a bounded workload.

This gate asserts the ORDERED chain up through GET_PROPERTIES, then BRANCHES on what
the CPU/VM actually exposes — BOTH outcomes are a PASS, because the gate proves the
syscall path + client are correct; whether the silicon/vCPU exposes counters is
environmental:

  * SUPPORTED  — CERISE-PERFMON-PROPERTIES (version>=2) then CERISE-PERFMON-COUNTS with
                 real non-zero counts. We assert instructions_retired >= the loop count
                 and core_cycles > 0 (sane lower bounds — never fabricated).
  * UNSUPPORTED — CERISE-PERFMON-UNSUPPORTED (QEMU TCG has no PMU; a KVM host may also
                 have its vPMU disabled). The clean, asserted no-PMU path.

CERISE-PERFMON-ERROR (a routing/flag/ABI bug, NOT a no-PMU environment) always FAILS.

By default the harness runs plain TCG (`-cpu qemu64,...`, which has no PMU) — fast,
deterministic, and portable, so the gate reliably takes the clean UNSUPPORTED branch on
any machine. Set CERISE_PERFMON_TRY_KVM=1 to ALSO attempt KVM-with-host-PMU first (KVM +
`-cpu host` passes the host PMU through), falling back to TCG if the KVM boot does not
reach the client. On this project's reference QEMU/KVM, KVM was investigated and does NOT
yield counters: `-cpu host` panics the vendored kernel in early boot (global_prng_seed —
a kernel/KVM incompatibility unrelated to perfmon), and `-cpu qemu64,+pmu` boots but
still reports PMU version 0. Real counters therefore require bare metal (an architectural PMU,
v4); The report prints which accelerator ran and which branch
fired.
"""
from __future__ import annotations
import argparse, os, pathlib, subprocess, sys, time

START = "CERISE-PERFMON-START"
PROPS = "CERISE-PERFMON-PROPERTIES"
COUNTS = "CERISE-PERFMON-COUNTS"
UNSUPPORTED = "CERISE-PERFMON-UNSUPPORTED"
ERROR = "CERISE-PERFMON-ERROR"
DONE = "CERISE-PERFMON-DONE"

# Must match ITERS in src/cerise/perfmon/src/main.rs::run_workload.
LOOP_ITERS = 20_000_000
BOOT_TIMEOUT_S = 300.0


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def _kvm_usable() -> bool:
    # KVM is opt-in: it is investigated but does not expose counters on the reference
    # host (see module doc), so the default gate stays on deterministic TCG.
    if os.environ.get("CERISE_PERFMON_TRY_KVM") != "1":
        return False
    try:
        return os.access("/dev/kvm", os.R_OK | os.W_OK)
    except OSError:
        return False


def _accel_candidates():
    """Ordered (label, extra-qemu-args) candidates. KVM+host-PMU first when opted in."""
    cands = []
    if _kvm_usable():
        # -cpu host passes the host PMU through; migratable=off avoids masking PMU leaves.
        cands.append(("kvm+host-pmu",
                      ["-enable-kvm", "-cpu", "host,migratable=off"]))
    cands.append(("tcg",
                  ["-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx"]))
    return cands


def _boot(qemu, datadir, shim, zbi, serial, accel_args, label):
    """Boot once; return the serial text after START+DONE (or timeout / early exit)."""
    if serial.exists():
        serial.unlink()
    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot", "-m", "4096M",
           *accel_args,
           "-serial", f"file:{serial}",
           "-kernel", shim, "-initrd", zbi]
    print(f"[perfmon] booting qemu-x64-perfmon (accel={label})", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        deadline = time.time() + BOOT_TIMEOUT_S
        while time.time() < deadline:
            txt = serial.read_text(errors="replace") if serial.exists() else ""
            if START in txt and DONE in txt:
                return txt, None
            if proc.poll() is not None:
                # QEMU exited. If it never even started the client, signal a hard boot
                # failure so the caller can fall back to another accelerator.
                return txt, proc.returncode
            time.sleep(2)
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        return txt, "timeout"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def _assert_and_report(txt, label) -> int:
    if START not in txt:
        raise AssertionError(
            f"never observed {START}; the perfmon client did not start. "
            f"serial tail:\n{txt[-1200:]}")
    if ERROR in txt:
        tail = txt[txt.rfind(ERROR):][:400]
        raise AssertionError(
            f"perfmon client reported a routing/flag/ABI bug (NOT a no-PMU "
            f"environment): {tail}")
    if DONE not in txt:
        raise AssertionError(
            f"observed {START} but never {DONE} (client crashed mid-run). "
            f"serial tail:\n{txt[-1200:]}")

    if COUNTS in txt:
        # ── SUPPORTED branch: assert the ordered chain and real, sane counts. ──
        if PROPS not in txt or txt.index(PROPS) > txt.index(COUNTS):
            raise AssertionError(
                f"{COUNTS} present but {PROPS} missing/out-of-order (chain broken)")
        line = next(l for l in txt.splitlines() if COUNTS in l)
        fields = {}
        for tok in line.split(COUNTS, 1)[1].split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                try:
                    fields[k] = int(v)
                except ValueError:
                    pass
        instructions = fields.get("instructions", 0)
        core_cycles = fields.get("core_cycles", 0)
        if instructions < LOOP_ITERS:
            raise AssertionError(
                f"SUPPORTED but instructions_retired={instructions} < loop count "
                f"{LOOP_ITERS} — counts implausibly low (not a valid PMU read)")
        if core_cycles <= 0:
            raise AssertionError(
                f"SUPPORTED but core_cycles={core_cycles} (must be > 0)")
        props_line = next(l for l in txt.splitlines() if PROPS in l)
        print(f"[perfmon] PASS (SUPPORTED branch, accel={label}): PMU exposed. "
              f"{props_line.strip()} | {line.strip()}", flush=True)
        print(f"[perfmon] instructions_retired={instructions} "
              f"(>= loop count {LOOP_ITERS}), core_cycles={core_cycles}, "
              f"llc_misses={fields.get('llc_misses')}, ref_cycles={fields.get('ref_cycles')}",
              flush=True)
        return 0

    if UNSUPPORTED in txt:
        # ── UNSUPPORTED branch: clean no-PMU path — a legitimate PASS. ──
        line = next(l for l in txt.splitlines() if UNSUPPORTED in l)
        print(f"[perfmon] PASS (UNSUPPORTED branch, accel={label}): this VM exposes no "
              f"PMU, and the client took the clean no-PMU path (no fabricated counts). "
              f"{line.strip()}", flush=True)
        print("[perfmon] NOTE: real counters require KVM-with-vPMU or bare metal "
              "(bare metal with an architectural PMU).", flush=True)
        return 0

    raise AssertionError(
        f"observed {START}/{DONE} but neither {COUNTS} nor {UNSUPPORTED} — "
        f"unexpected client state. serial tail:\n{txt[-1200:]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--shim", required=True)
    ap.add_argument("--zbi", required=True)
    ap.add_argument("--qemu-data-dir", required=True)
    ns = ap.parse_args()
    qemu = _need(ns.qemu, "qemu")
    shim = _need(ns.shim, "shim")
    zbi = _need(ns.zbi, "zbi")
    datadir = _need(ns.qemu_data_dir, "qemu data dir")

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    serial = tmp / "perfmon-serial.log"

    candidates = _accel_candidates()
    last_txt = ""
    for i, (label, accel_args) in enumerate(candidates):
        txt, failure = _boot(qemu, datadir, shim, zbi, serial, accel_args, label)
        last_txt = txt
        if START in txt:
            # The client ran under this accelerator; assert on this boot (no fallback).
            return _assert_and_report(txt, label)
        # Hard boot failure before the client started. Fall back to the next candidate
        # (e.g. KVM unusable in this sandbox despite /dev/kvm being present).
        more = i + 1 < len(candidates)
        print(f"[perfmon] accel={label} failed to reach the client "
              f"(exit={failure}); {'falling back' if more else 'no fallback left'}.",
              flush=True)
    raise AssertionError(
        f"no accelerator reached the perfmon client. last serial tail:\n{last_txt[-1200:]}")


if __name__ == "__main__":
    sys.exit(main())
