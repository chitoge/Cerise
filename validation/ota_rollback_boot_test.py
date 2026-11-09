#!/usr/bin/env python3
"""OTA A/B rollback gate: the boot shim rolls back a broken slot to a good one.

Proves the shim's slot-selection + rollback + \\abr write-back persistence,
with ZERO dependency on the in-OS updater. The ESP (a real protective-MBR/GPT
disk from uefi_disk_image, booted under OVMF exactly like real hardware) is
staged by the build with:

  \\zircon_a.zbi  = //products:x64-smoke     (a good image; prints CERISE-SMOKE-OK)
  \\zircon_b.zbi  = a TRUNCATED ZBI           (fails the shim's ZBI load)
  \\abr           = active=B, tries=[A:0,B:1], successful=[A:1,B:0]

Launch 1 (the rollback): the shim picks B (active + one try), spends the try
(writes \\abr), tries to load the truncated \\zircon_b.zbi, fails BEFORE
ExitBootServices, and falls back IN-PROCESS to slot A — writing \\abr with
active=A — which boots. Asserts, in order:
    CERISE-ABR-SLOT=B  ->  CERISE-ABR-FALLBACK  ->  CERISE-ABR-SLOT=A  ->  CERISE-SMOKE-OK

Launch 2 (persistence of the rollback): SAME disk, whose \\abr now reads
active=A/successful. The shim boots straight to A with NO fallback and never
retries B. Asserts CERISE-ABR-SLOT=A -> CERISE-SMOKE-OK and that
CERISE-ABR-FALLBACK / CERISE-ABR-SLOT=B are ABSENT — i.e. the rollback the
shim wrote in launch 1 survived the reboot on the physical disk.
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

SMOKE_OK = "CERISE-SMOKE-OK"
SLOT_A = "CERISE-ABR-SLOT=A"
SLOT_B = "CERISE-ABR-SLOT=B"
FALLBACK = "CERISE-ABR-FALLBACK"
# The truncated \zircon_b.zbi makes the shim print "Failed to load ZBI" — that is
# EXPECTED here, so it is NOT a failure marker. Real failures:
FAIL_MARKERS = ["CERISE-ABR-NO-BOOTABLE", "CERISE-ABR-WRITE-FAIL",
                "KERNEL PANIC", "triple fault", "KERNEL FAULT"]
BOOT_TIMEOUT_S = 240.0


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def _wait_for(serial, needle, proc, deadline):
    while time.time() < deadline:
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        if needle in txt:
            return txt
        for fm in FAIL_MARKERS:
            if fm in txt:
                raise AssertionError(f"guest failure marker {fm!r}: {txt[txt.rfind(fm):][:400]}")
        if proc.poll() is not None:
            raise AssertionError(f"QEMU exited early (rc={proc.returncode})\n{txt[-1200:]}")
        time.sleep(2)
    raise AssertionError(f"timed out waiting for {needle!r}\n"
                         f"{(serial.read_text(errors='replace') if serial.exists() else '')[-1800:]}")


def _assert_ordered(txt, markers):
    last = -1
    for m in markers:
        i = txt.find(m, last + 1)
        if i < 0:
            raise AssertionError(f"missing expected marker {m!r} on serial\n--- tail ---\n{txt[-1800:]}")
        last = i


def boot(qemu, datadir, code, ovmf_vars, disk, serial, qemu_mem="2048M"):
    if serial.exists():
        serial.unlink()
    # Attach the ESP/GPT disk on the q35 built-in AHCI controller, writable and
    # write-through so the shim's UEFI-SFS \abr write reaches the backing file
    # before the next launch reads it. No snapshot => persistent across launches.
    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot", "-m", qemu_mem,
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
           "-drive", f"if=pflash,format=raw,file={ovmf_vars}",
           "-drive", f"if=none,id=ota,format=raw,cache=writethrough,file={disk}",
           "-device", "ide-hd,drive=ota,bus=ide.0"]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    return proc


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


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
    disk_src = _need(ns.disk, "ota-rollback disk image")

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    ovmf_vars = tmp / "OVMF_VARS.fd"
    shutil.copyfile(vars_src, ovmf_vars)
    os.chmod(ovmf_vars, 0o644)
    # uefi_disk_image emits a gzip image; decompress to ONE writable disk file
    # reused across both launches (this is what carries \abr persistence).
    disk = tmp / "ota-rollback-disk.img"
    with open(disk_src, "rb") as f:
        magic = f.read(2)
    if magic == b"\x1f\x8b":
        with gzip.open(disk_src, "rb") as src, open(disk, "wb") as dst:
            shutil.copyfileobj(src, dst)
    else:
        shutil.copyfile(disk_src, disk)
    os.chmod(disk, 0o644)

    # ---- Launch 1: broken slot B -> in-process fallback to slot A. ----
    serial1 = tmp / "ota-rollback-1.log"
    proc = boot(qemu, datadir, code, ovmf_vars, disk, serial1)
    try:
        print("[ota-rollback] launch 1: shim should try B, fail, roll back to A", flush=True)
        deadline = time.time() + BOOT_TIMEOUT_S
        _wait_for(serial1, SMOKE_OK, proc, deadline)
        txt = serial1.read_text(errors="replace")
        _assert_ordered(txt, [SLOT_B, FALLBACK, SLOT_A, SMOKE_OK])
        print("[ota-rollback] launch 1 OK: SLOT=B -> FALLBACK -> SLOT=A -> SMOKE-OK", flush=True)
    finally:
        stop(proc)

    # ---- Launch 2: the rollback persisted; boot straight to A, no fallback. ----
    serial2 = tmp / "ota-rollback-2.log"
    proc = boot(qemu, datadir, code, ovmf_vars, disk, serial2)
    try:
        print("[ota-rollback] launch 2: \\abr now active=A; expect A with no fallback", flush=True)
        deadline = time.time() + BOOT_TIMEOUT_S
        _wait_for(serial2, SMOKE_OK, proc, deadline)
        txt = serial2.read_text(errors="replace")
        _assert_ordered(txt, [SLOT_A, SMOKE_OK])
        if FALLBACK in txt:
            raise AssertionError("launch 2 unexpectedly rolled back again (rollback did not persist)")
        if SLOT_B in txt:
            raise AssertionError("launch 2 unexpectedly tried slot B (rollback did not persist)")
        print("[ota-rollback] launch 2 OK: SLOT=A, no fallback, no B (rollback persisted)", flush=True)
    finally:
        stop(proc)

    print("[ota-rollback] PASS", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
