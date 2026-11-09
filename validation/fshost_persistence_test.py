#!/usr/bin/env python3
"""Cerise fshost PERSISTENCE across reboots (through the fshost mount path).

Boots //products:qemu-x64-storage TWICE against the SAME NVMe image (no truncation between
boots):

  Boot 1 (blank disk): the fxfs_provisioner FORMATS + creates "blob"
      (CERISE-PROVISION-FORMAT-OK); fshost then finds no data/unencrypted volumes and
      CREATES them (INIT-DATA-VOLUME-CREATE-DATA-VOLUME-OK) + auto-mounts, and the probe
      reads/writes a file (CERISE-FSHOST-READ-OK).
  Boot 2 (same disk): the provisioner is IDEMPOTENT — it sniffs Fxfs + finds "blob" and
      SKIPS (CERISE-PROVISION-SKIP); fshost then finds all volumes present and UNLOCKS the
      EXISTING encrypted data volume via its keybag (NO reformat: INIT-DATA-VOLUME-*
      absent), auto-mounts (PROCESS-DEVICE-MOUNT-DATA-VOLUME-OK), and the probe again
      reads/writes (CERISE-FSHOST-READ-OK).

Proves the fshost-path durability claim: the on-disk Fxfs container + encrypted data
volume + keybag survive a reboot and are re-opened (not reformatted). Byte-level fxfs
durability is separately proven by //validation:fileserver-persistence (in-process path).
"""
from __future__ import annotations
import argparse, os, pathlib, subprocess, sys, time

READ_OK = "CERISE-FSHOST-READ-OK"
FAIL_MARKERS = ["CERISE-PROVISION-FAIL", "CERISE-FSHOST-READ-FAIL"]
FORBIDDEN = ["panic", "triple fault", "KERNEL FAULT", "FATAL ERROR"]
BOOT_TIMEOUT_S = 400.0
REFORMAT_MARKER = "INIT-DATA-VOLUME-CREATE-DATA-VOLUME-OK"


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
           "-drive", f"file={nvme},if=none,format=raw,id=nvm0",
           "-device", "nvme,drive=nvm0,serial=deadbeef",
           "-kernel", shim, "-initrd", zbi]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    deadline = time.time() + BOOT_TIMEOUT_S
    txt = ""
    while time.time() < deadline:
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        if READ_OK in txt:
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
    raise AssertionError(f"timed out waiting for {READ_OK}\n{txt[-1500:]}")


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


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
    nvme = tmp / "fshost-persist-nvme.img"
    with open(nvme, "wb") as f:  # created ONCE, reused across BOTH boots
        f.truncate(256 * 1024 * 1024)

    # --- Boot 1: fresh disk -> provisioner formats, fshost CREATES the data volume ------
    t0 = time.time()
    proc, txt1 = boot(qemu, shim, zbi, datadir, nvme, tmp / "fshost-persist-1.log")
    try:
        assert "CERISE-PROVISION-FORMAT-OK" in txt1, "boot 1 should format the blank disk"
        assert REFORMAT_MARKER in txt1, "boot 1 fshost should CREATE the data volume"
        print(f"[fshost-persist] boot 1 ({time.time()-t0:.0f}s): formatted + data volume created "
              f"+ read/write OK", flush=True)
    finally:
        stop(proc)

    # --- Boot 2: SAME disk -> provisioner SKIPs, fshost UNLOCKS the existing data volume -
    t1 = time.time()
    proc, txt2 = boot(qemu, shim, zbi, datadir, nvme, tmp / "fshost-persist-2.log")
    try:
        assert "CERISE-PROVISION-SKIP" in txt2, \
            "boot 2 provisioner should SKIP (disk already Fxfs with a blob volume)"
        assert "PROCESS-DEVICE-MOUNT-DATA-VOLUME-OK" in txt2, "boot 2 fshost should auto-mount"
        assert REFORMAT_MARKER not in txt2, \
            "boot 2 fshost must UNLOCK the existing data volume (keybag), NOT reformat it"
        print(f"[fshost-persist] boot 2 ({time.time()-t1:.0f}s): provisioner SKIP + fshost UNLOCKED "
              f"the existing encrypted data volume (no reformat) + read/write OK", flush=True)
    finally:
        stop(proc)

    print("[fshost-persist] PASS: the fxfs container + encrypted data volume survived a reboot "
          "and fshost re-opened them (not reformat).", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
