#!/usr/bin/env python3
"""Cerise gRPC gate: fxfs PERSISTENCE across reboots (format-if-needed proof).

Boots //products:qemu-x64-fileserver TWICE against the SAME NVMe image (no
truncation between boots, no QEMU snapshot):

  Boot 1: the blank disk -> fxfs format (CERISE-FILESERVER-FXFS-FORMATTED); the host
          Writes persist.txt=<bytes> (synced to the fxfs journal), then QEMU stops.
  Boot 2: the same disk -> fxfs OPEN-existing (CERISE-FILESERVER-FXFS-OPENED); the
          host Reads persist.txt and asserts the exact bytes written in boot 1
          survived. Guest emits CERISE-FILESERVER-PERSIST-OK.

Proves real durability (open-existing fxfs), not format-on-blank.
"""
from __future__ import annotations
import argparse, os, pathlib, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from grpc_h2 import GrpcConn, pb_str, pb_bytes, pb_uint, pb_bool, pb_decode

SVC = "/cerise.fileserver.v1.FileServer"
LISTENING = "CERISE-FILESERVER-LISTENING"
FAIL = "CERISE-FILESERVER-FAIL"
# See fileserver_grpc_boot_test.py: a refusal on this blank disk (boot 1) or on the
# Fxfs container we ourselves wrote (boot 2) is a regression, not a pass.
DEGRADED = "CERISE-FILESERVER-DEGRADED"
BOOT_TIMEOUT_S = 600.0
PAYLOAD = b"persist-across-reboot-cerise-fxfs\n"


def _need(p, what):
    if not p or not os.path.exists(p):
        raise SystemExit(f"{what} not found: {p}")
    return p


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def boot(qemu, shim, zbi, datadir, nvme, serial):
    if serial.exists():
        serial.unlink()
    port = _free_port()
    cmd = [qemu, "-L", datadir, "-machine", "q35", "-nographic", "-monitor", "none",
           "-no-reboot", "-m", "4096M",
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:50051",
           "-device", "virtio-net-pci,disable-legacy=on,netdev=net0,romfile=",
           "-drive", f"file={nvme},if=none,format=raw,id=nvm0",
           "-device", "nvme,drive=nvm0,serial=deadbeef",
           "-kernel", shim, "-initrd", zbi]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    deadline = time.time() + BOOT_TIMEOUT_S
    while time.time() < deadline:
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        # All failure markers before the success needle: a degraded file server
        # still reaches LISTENING, so needle-first would let it pass.
        if DEGRADED in txt:
            proc.terminate()
            raise AssertionError(f"file server has no filesystem: {txt[txt.rfind(DEGRADED):][:400]}")
        if FAIL in txt:
            proc.terminate()
            raise AssertionError(f"guest failure: {txt[txt.rfind(FAIL):][:300]}")
        if LISTENING in txt:
            return proc, port
        if proc.poll() is not None:
            raise AssertionError(f"QEMU exited early ({proc.returncode})")
        time.sleep(3)
    proc.terminate()
    raise AssertionError("timed out waiting for LISTENING")


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
    nvme = tmp / "persist-nvme.img"
    with open(nvme, "wb") as f:  # created ONCE, reused across both boots
        f.truncate(256 * 1024 * 1024)

    # --- Boot 1: format + write -------------------------------------------
    s1 = tmp / "persist-serial-1.log"
    proc, port = boot(qemu, shim, zbi, datadir, nvme, s1)
    try:
        assert "CERISE-FILESERVER-FXFS-FORMATTED" in s1.read_text(errors="replace"), \
            "boot 1 should format the blank disk"
        c = GrpcConn("127.0.0.1", port)
        msg, st, _ = c.call(SVC + "/Write",
                            pb_str(1, "persist.txt") + pb_uint(2, 0) + pb_bytes(3, PAYLOAD)
                            + pb_bool(4, True) + pb_bool(5, True))
        assert st == 0 and pb_decode(msg[0]).get(1) == len(PAYLOAD), f"Write {st} {msg}"
        c.close()
        print(f"[persist] boot 1: formatted + Wrote persist.txt = {PAYLOAD!r}", flush=True)
    finally:
        stop(proc)

    # --- Boot 2: open-existing + read -------------------------------------
    s2 = tmp / "persist-serial-2.log"
    proc, port = boot(qemu, shim, zbi, datadir, nvme, s2)
    try:
        assert "CERISE-FILESERVER-FXFS-OPENED" in s2.read_text(errors="replace"), \
            "boot 2 should OPEN the existing fxfs, not reformat"
        c = GrpcConn("127.0.0.1", port)
        msgs, st, _ = c.call(SVC + "/Read",
                             pb_str(1, "persist.txt") + pb_uint(2, 0)
                             + pb_uint(3, len(PAYLOAD)),
                             streaming=True)
        assert st == 0, f"Read status {st}"
        got = b"".join(pb_decode(m).get(1, b"") for m in msgs)
        assert got == PAYLOAD, f"persisted bytes mismatch: {got!r} != {PAYLOAD!r}"
        c.call(SVC + "/Stat", pb_str(1, "__cerise_persist_ok__"))  # guest marker
        c.close()
        print(f"[persist] boot 2: opened existing fxfs + Read persist.txt = {got!r}  SURVIVED",
              flush=True)
        deadline = time.time() + 20
        while time.time() < deadline:
            if "CERISE-FILESERVER-PERSIST-OK" in s2.read_text(errors="replace"):
                break
            time.sleep(1)
        else:
            raise AssertionError("guest CERISE-FILESERVER-PERSIST-OK not observed")
    finally:
        stop(proc)

    print("[persist] PASS: fxfs data survived a reboot (write boot-1, read boot-2)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
