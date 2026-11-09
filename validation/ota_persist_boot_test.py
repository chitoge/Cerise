#!/usr/bin/env python3
"""OTA A/B persistence gate: a committed slot B keeps booting B (no re-apply).

The companion to //validation:ota-update-boot. That gate proves apply ->
boot-the-new-slot -> commit across two launches; this gate proves the *fourth*
step — that once slot B is committed, a later reboot still boots B and does not
re-run the update — using a PRE-STAGED committed-B disk so it needs only ONE
QEMU launch (keeping each gate's runtime well under the foreground cap).

The ESP is staged by the build with:
  \\zircon_a.zbi = qemu-x64-ota      (v1)
  \\zircon_b.zbi = qemu-x64-ota-v2   (v2, the committed image)
  \\abr          = active=B, tries=[A:0,B:2], successful=[A:1,B:1]

Boot: the shim sees B active + committed -> CERISE-ABR-SLOT=B (no fallback);
slot B is v2 -> CERISE-OS-VERSION=2; the updater's success-commit sees B already
successful -> CERISE-OTA-PERSISTED and, because v2's config has apply=false, it
does NOT fetch/apply/reboot. Asserts SLOT=B + OS-VERSION=2 + PERSISTED are
present and CERISE-OTA-APPLIED / CERISE-ABR-FALLBACK are ABSENT.
"""
from __future__ import annotations
import argparse
import gzip
import os
import pathlib
import shutil
import subprocess
import sys
import time

SLOT_B = "CERISE-ABR-SLOT=B"
FALLBACK = "CERISE-ABR-FALLBACK"
OS_V2 = "CERISE-OS-VERSION=2"
PERSISTED = "CERISE-OTA-PERSISTED"
APPLIED = "CERISE-OTA-APPLIED"
FAIL_MARKERS = ["CERISE-OTA-FAIL", "CERISE-ABR-NO-BOOTABLE", "KERNEL PANIC",
                "triple fault", "KERNEL FAULT"]
BOOT_TIMEOUT_S = 500.0


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def boot(qemu, datadir, code, ovmf_vars, disk, serial):
    if serial.exists():
        serial.unlink()
    # -enable-kvm: the heavy AHCI + netstack3 product boots ~10x faster under KVM
    # than pure-TCG (~700s AHCI bind). Keep the controlled qemu64 CPU model (NOT
    # -cpu host, which page-faults the Zircon kernel early). Fall back to TCG.
    accel = ["-enable-kvm"] if os.access("/dev/kvm", os.R_OK | os.W_OK) else []
    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot", "-m", "4096M", *accel,
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-netdev", "user,id=net0",
           "-device", "virtio-net-pci,disable-legacy=on,netdev=net0,romfile=",
           "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
           "-drive", f"if=pflash,format=raw,file={ovmf_vars}",
           "-drive", f"if=none,id=ota,format=raw,cache=writeback,file={disk}",
           "-device", "ide-hd,drive=ota,bus=ide.0"]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def wait_for(serial, needle, proc, deadline):
    while time.time() < deadline:
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        if needle in txt:
            return txt
        for fm in FAIL_MARKERS:
            if fm in txt:
                raise AssertionError(f"guest failure marker {fm!r}:\n{txt[txt.rfind(fm):][:500]}")
        if proc.poll() is not None:
            raise AssertionError(f"QEMU exited early (rc={proc.returncode})\n{txt[-1500:]}")
        time.sleep(2)
    raise AssertionError(f"timed out waiting for {needle!r}\n"
                         f"{(serial.read_text(errors='replace') if serial.exists() else '')[-1800:]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--qemu-data-dir", required=True)
    ap.add_argument("--ovmf-code", required=True)
    ap.add_argument("--ovmf-vars", required=True)
    ap.add_argument("--disk", required=True)
    ns = ap.parse_args()
    qemu = _need(ns.qemu, "qemu")
    datadir = _need(ns.qemu_data_dir, "qemu data dir")
    code = _need(ns.ovmf_code, "OVMF_CODE")
    vars_src = _need(ns.ovmf_vars, "OVMF_VARS")
    disk_src = _need(ns.disk, "ota-persist disk image")

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    ovmf_vars = tmp / "OVMF_VARS.fd"
    shutil.copyfile(vars_src, ovmf_vars)
    os.chmod(ovmf_vars, 0o644)
    disk = tmp / "ota-persist-disk.img"
    with open(disk_src, "rb") as f:
        magic = f.read(2)
    if magic == b"\x1f\x8b":
        with gzip.open(disk_src, "rb") as src, open(disk, "wb") as dst:
            shutil.copyfileobj(src, dst)
    else:
        shutil.copyfile(disk_src, disk)
    os.chmod(disk, 0o644)

    serial = tmp / "ota-persist.log"
    proc = boot(qemu, datadir, code, ovmf_vars, disk, serial)
    try:
        print("[ota-persist] boot committed-B disk: expect B/v2, PERSISTED, no re-apply",
              flush=True)
        deadline = time.time() + BOOT_TIMEOUT_S
        wait_for(serial, PERSISTED, proc, deadline)
        time.sleep(4)  # give any (unexpected) apply/reboot a chance to show, then assert absent
        txt = serial.read_text(errors="replace")
        for m in (SLOT_B, OS_V2, PERSISTED):
            if m not in txt:
                raise AssertionError(f"missing expected marker {m!r}\n--- tail ---\n{txt[-1800:]}")
        if FALLBACK in txt:
            raise AssertionError("committed slot B unexpectedly rolled back (FALLBACK present)")
        if APPLIED in txt:
            raise AssertionError("committed slot B unexpectedly re-applied the update")
        print("[ota-persist] PASS: SLOT=B, OS-VERSION=2, PERSISTED, no fallback, no re-apply",
              flush=True)
    finally:
        stop(proc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
