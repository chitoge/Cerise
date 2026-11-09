#!/usr/bin/env python3
"""Cerise fshost-boot gate: fshost owns the disk lifecycle, race-free.

Boots //products:qemu-x64-storage (root_dfv2acpi_fshost.cm) via the direct-kernel path
with a SINGLE fresh NVMe disk (a fresh image every run => every run is a clean FIRST
boot, so the provisioning marker must appear). Asserts, in order on serial:

  1. drivers bind (platform-bus/ACPI/PCI + the NVMe block driver),
  2. first-boot PROVISIONING: the fxfs_provisioner formats the virgin disk and creates
     the "blob" volume, then RELEASES it and serves its readiness gate
     (CERISE-PROVISION-FORMAT-OK -> CERISE-PROVISION-READY),
  3. fshost's OWN auto-mount of the data volume — fshost's real debug_log marker
     PROCESS-DEVICE-MOUNT-DATA-VOLUME-OK (not just inferred),
  4. a userspace consumer (fshost_probe) writes THEN reads a real file back through
     fshost's exported "/fshost-fs/data" directory (CERISE-FSHOST-MOUNT-OK ->
     CERISE-FSHOST-READ-OK) — real proof, not a "mounted" log,

with ZERO panics/faults and no *-FAIL marker. The provisioner-then-fshost ordering is a
real routed capability dependency (fshost_probe gates on the provisioner's "provisioned"
directory), so this is deterministic across runs — run the target 3x to prove the old
fxfs_probe-vs-fshost device-contention race is gone.
"""
from __future__ import annotations
import argparse, os, pathlib, subprocess, sys, time

# Success is the final consumer readback; the earlier markers are ordering checkpoints.
SUCCESS = "CERISE-FSHOST-READ-OK"
# Required markers in the order they must appear on serial.
ORDERED = [
    "CERISE-PLATFORM-BUS-OK",           # platform-bus/ACPI up
    "CERISE-PCI-ENUM",                  # PCI enumerated
    "CERISE-NVME-BOUND",                # the block driver bound the disk
    "CERISE-PROVISION-FORMAT-OK",       # first-boot: virgin disk formatted as Fxfs
    "CERISE-PROVISION-BLOB-VOLUME-OK",  # first-boot: "blob" volume created
    "CERISE-PROVISION-READY",           # provisioner released the disk + serving the gate
    "CERISE-FSHOST-PROBE-PROVISIONED-OBSERVED",  # fshost_probe passed the routed gate
    "PROCESS-DEVICE-MOUNT-DATA-VOLUME-OK",       # fshost's OWN data-volume auto-mount
    "CERISE-FSHOST-MOUNT-OK",           # consumer wrote a file through /fshost-fs/data
    SUCCESS,                            # consumer read it back, bytes matched
]
FAIL_MARKERS = ["CERISE-PROVISION-FAIL", "CERISE-FSHOST-READ-FAIL"]
# NB: netdev_probe (inherited from the shared driver stack) exits 1 every boot here — this
# disk-only QEMU config has no NIC to bind — logging a benign component_manager
# "abnormal return code" WARN. It is an independent Eager component that never touches the
# disk, so it is deliberately NOT a failure/forbidden marker; the fshost path is unaffected.
FORBIDDEN = ["panic", "triple fault", "KERNEL FAULT", "FATAL ERROR"]
# The dominant cost is NVMe bind (~180-200s on this host) + fxfs format + fshost's own
# content-sniff -> spawn crypt -> create data/unencrypted -> mount sequence. Bounded to
# stay under the gate's --test_timeout=520.
BOOT_TIMEOUT_S = 500.0


def _need(p, what):
    if not p or not os.path.exists(p):
        raise SystemExit(f"{what} not found: {p}")
    return p


def boot(qemu, shim, zbi, datadir, nvme, serial):
    if serial.exists():
        serial.unlink()
    cmd = [qemu, "-L", datadir, "-machine", "q35", "-nographic", "-monitor", "none",
           "-no-reboot", "-m", "4096M",
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           # A single NVMe disk => exactly one block.volume.Service instance, so the
           # provisioner and fshost operate on the same, sole disk deterministically.
           "-drive", f"file={nvme},if=none,format=raw,id=nvm0",
           "-device", "nvme,drive=nvm0,serial=deadbeef",
           "-kernel", shim, "-initrd", zbi]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    deadline = time.time() + BOOT_TIMEOUT_S
    txt = ""
    while time.time() < deadline:
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        if SUCCESS in txt:
            return proc, txt
        for fm in FAIL_MARKERS:
            if fm in txt:
                proc.terminate()
                raise AssertionError(f"guest failure ({fm}):\n{txt[txt.rfind(fm):][:400]}")
        for fb in FORBIDDEN:
            if fb in txt:
                proc.terminate()
                raise AssertionError(f"forbidden marker ({fb}):\n{txt[txt.rfind(fb):][:400]}")
        if proc.poll() is not None:
            raise AssertionError(f"QEMU exited early ({proc.returncode})\n{txt[-800:]}")
        time.sleep(3)
    proc.terminate()
    raise AssertionError(f"timed out waiting for {SUCCESS}\n{txt[-1500:]}")


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


def assert_ordered(txt):
    last = -1
    for m in ORDERED:
        i = txt.find(m)
        assert i != -1, f"missing required marker: {m}"
        assert i > last, f"marker out of order: {m} appeared before a prior required marker"
        last = i
    for fb in FORBIDDEN:
        assert fb not in txt, f"forbidden marker present: {fb}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--shim", required=True)
    ap.add_argument("--zbi", required=True)
    ap.add_argument("--qemu-data-dir", required=True)
    ns = ap.parse_args()
    qemu, shim = _need(ns.qemu, "qemu"), _need(ns.shim, "shim")
    zbi, datadir = _need(ns.zbi, "zbi"), _need(ns.qemu_data_dir, "qemu data dir")

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    nvme = tmp / "fshost-nvme.img"
    with open(nvme, "wb") as f:  # fresh blank disk => a clean FIRST boot every run
        f.truncate(256 * 1024 * 1024)

    serial = tmp / "fshost-serial.log"
    t0 = time.time()
    proc, txt = boot(qemu, shim, zbi, datadir, nvme, serial)
    try:
        assert_ordered(txt)
        print(f"[fshost-boot] PASS in {time.time() - t0:.0f}s: provision -> fshost auto-mount "
              f"-> userspace read/write verified (race-free).", flush=True)
    finally:
        stop(proc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
