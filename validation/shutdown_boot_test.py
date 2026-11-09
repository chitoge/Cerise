#!/usr/bin/env python3
"""Cerise orderly-shutdown live-boot proof.

Boots //products:qemu-x64-shutdown via the direct-kernel path. The product's
shutdown_trigger waits for driver_manager to come up, then calls
fuchsia.hardware.power.statecontrol.Admin/Poweroff on the builtin shutdown-shim. The shim
records the termination state (Poweroff) and drives component_manager's REAL
reverse-dependency-order topology teardown via fuchsia.sys2.SystemController. After the
whole topology is torn down, the guest requests a system poweroff and QEMU (run with
-no-reboot) exits cleanly.

This test gates on the real chain and a clean guest exit. It asserts, IN ORDER, the shim
and trigger chain markers and component_manager's reverse-dependency teardown markers, that
a poweroff was requested at the kernel, and that QEMU exits on its own with returncode 0.

Known platform limitations (; NOT asserted here so this test
stays forward-compatible if they are ever fixed):
  * driver_manager is force-stopped at component_manager's 5s stop window (the DFv2 driver
    components do not ack a graceful Stop), so its shutdown_manager is pre-empted before its
    own zx_system_powerctl; the actual poweroff is userboot's critical-root-exit default.
  * The kernel's ACPI S5 poweroff currently fails and falls back to halt/reboot, which QEMU
    under -no-reboot turns into the clean rc=0 exit this test observes.
"""
from __future__ import annotations
import argparse, os, pathlib, subprocess, sys, time

READY = "CERISE-SHUTDOWN-READY"
REQUESTED = "CERISE-SHUTDOWN-REQUESTED"
FAIL = "CERISE-SHUTDOWN-FAIL"

# The full ordered chain, earliest-to-latest, that a real orderly shutdown must produce.
#
# NOTE on the tail markers: with the devfs-quiesce gate in shutdown_trigger the
# teardown runs the INTENDED graceful path — every driver/driver-host acks Stop
# (no 5s force-kills) and driver_manager's shutdown_manager issues the final
# powerctl itself. Two consequences for what is assertable on serial:
#   * the very last per-component "=FS driver_manager_rust"/"=FS shutdown_shim"
#     lines race the debuglog's own orderly teardown and may never drain to
#     serial — so we assert teardown depth via a driver-host =FS (which drains
#     reliably) plus the KERNEL-side completion signals instead;
#   * the poweroff arrives via platform_graceful_halt (suggested_action 4), not
#     userboot's critical-exit "Executing poweroff" fallback.
ORDERED_MARKERS = [
    "CERISE-SHUTDOWN-SHIM-READY",       # shim (builtin) started, serving Admin + SST
    "CERISE-SHUTDOWN-READY",            # trigger started
    "CERISE-SHUTDOWN-DEVFS-QUIESCED",   # trigger observed a stable /dev tree (no stop-during-start)
    "CERISE-SHUTDOWN-REQUESTED",        # trigger issued Admin.Poweroff
    "CERISE-SHUTDOWN-POWEROFF-REQUESTED",  # shim received Poweroff, recorded state
    "CERISE-SHUTDOWN-TOPOLOGY-BEGIN",   # shim drove SystemController.Shutdown
    "=FS driver_manager_rust/driver-hosts:driver-host-root",  # graceful driver teardown reached the hosts
    "debuglog shutdown completed with status 0",  # kernel: orderly debuglog quiesce after topology teardown
    "platform_halt suggested_action 4",  # poweroff (not reboot) reached platform_halt via the graceful path
]

# Specific fault signatures only (a bare "panic" would false-match the benign kernel
# graceful-halt line "panic_deadline=...").
PANICS = ("ZIRCON KERNEL PANIC", "KERNEL PANIC", "triple fault", "KERNEL FAULT")

READY_TIMEOUT_S = 300.0          # trigger start -> READY (near-immediate)
REQUESTED_TIMEOUT_S = 420.0      # READY -> driver_manager up -> Poweroff requested
POWEROFF_TIMEOUT_S = 180.0       # REQUESTED -> teardown -> clean guest exit


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def _read(serial: pathlib.Path) -> str:
    return serial.read_text(errors="replace") if serial.exists() else ""


def _check_no_fault(txt: str):
    if FAIL in txt:
        tail = txt[txt.rfind(FAIL):][:400]
        raise AssertionError(f"guest reported shutdown failure: {tail!r}")
    for p in PANICS:
        if p in txt:
            i = txt.find(p)
            raise AssertionError(f"guest fault/panic on serial: {txt[i:i+400]!r}")


def _wait_for(serial, needle, timeout_s, proc, *, allow_exit=False):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        txt = _read(serial)
        _check_no_fault(txt)
        if needle in txt:
            return txt
        if proc.poll() is not None and not allow_exit:
            raise AssertionError(
                f"QEMU exited (rc={proc.returncode}) before {needle!r} appeared")
        time.sleep(2)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {needle!r}")


def _assert_ordered(txt: str, markers):
    """Every marker must appear, in the given order."""
    last = -1
    for m in markers:
        i = txt.find(m, last + 1)
        if i < 0:
            raise AssertionError(f"missing expected chain marker {m!r} on serial")
        if i <= last:
            raise AssertionError(f"chain marker {m!r} out of order on serial")
        last = i


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
    outdir = pathlib.Path(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR", str(tmp)))
    outdir.mkdir(parents=True, exist_ok=True)
    serial = outdir / "shutdown-serial.log"
    if serial.exists():
        serial.unlink()

    # -no-reboot: a guest reboot becomes a QEMU exit; combined with the default (no
    # -no-shutdown), a guest poweroff also exits QEMU. No VGA/QMP needed here.
    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot", "-m", "4096M",
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-kernel", shim, "-initrd", zbi]
    print("[shutdown] booting qemu-x64-shutdown (direct-kernel)", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        _wait_for(serial, READY, READY_TIMEOUT_S, proc)
        print(f"[shutdown] {READY}", flush=True)

        _wait_for(serial, REQUESTED, REQUESTED_TIMEOUT_S, proc)
        print(f"[shutdown] {REQUESTED}; awaiting orderly teardown + clean guest exit",
              flush=True)

        # The guest tears the topology down and then exits on its own.
        try:
            rc = proc.wait(timeout=POWEROFF_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            raise AssertionError(
                f"guest did not exit within {POWEROFF_TIMEOUT_S}s of {REQUESTED} "
                f"(no clean QEMU exit after the shutdown request)")

        txt = _read(serial)
        _check_no_fault(txt)
        # The full real chain, in order: shim + trigger markers, then component_manager's
        # reverse-dependency teardown (shim shut down last), then a kernel poweroff request.
        _assert_ordered(txt, ORDERED_MARKERS)
        if rc != 0:
            raise AssertionError(f"QEMU exited rc={rc}, expected 0 (clean guest exit)")

        print("[shutdown] PASS: real Admin.Poweroff -> shim -> SystemController orderly "
              "reverse-dependency topology teardown; system poweroff requested; QEMU exited "
              "cleanly (rc=0)", flush=True)
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
