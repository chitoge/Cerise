#!/usr/bin/env python3
"""Cerise gRPC gate storage-backed integration+4 live end-to-end test: real files over gRPC/netstack3.

Boots //products:qemu-x64-fileserver via the direct-kernel path (the -kernel/-initrd
recipe run-qemu.sh uses for netstack3-sized ZBIs; the rules_ostest FAT32 ESP tool
does not scale to the ~1.6 GiB ZBI) WITH an NVMe scratch disk. The guest fileserver
brings up netstack3, mounts fxfs RW in-process on the NVMe block device
(CERISE-FILESERVER-FXFS-MOUNTED -> LISTENING), and serves gRPC. Then a HOST
dependency-free HTTP/2 gRPC client (grpc_h2.py) drives the full real-file sequence
through QEMU SLIRP hostfwd:

  Write hello.txt=<bytes> -> Read back (assert equal) -> Stat (assert size) ->
  List root (assert hello.txt present) -> Mkdir d -> Rename hello.txt -> d/renamed.txt
  -> Stat d/renamed.txt (assert size) -> Stat hello.txt (assert NOT_FOUND grpc-status)
  -> Delete d/renamed.txt -> Read d/renamed.txt (assert NOT_FOUND grpc-status).

grpc-status trailers ARE decoded (HPACK) and checked. The guest emits
CERISE-FILESERVER-E2E-OK when the host Stats a sentinel after every step passes.
"""
from __future__ import annotations
import argparse, os, pathlib, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from grpc_h2 import GrpcConn, pb_str, pb_bytes, pb_uint, pb_bool, pb_decode

SVC = "/cerise.fileserver.v1.FileServer"
LISTENING = "CERISE-FILESERVER-LISTENING"
FAIL = "CERISE-FILESERVER-FAIL"
# The file server now REFUSES to format a disk it cannot prove is blank, and serves
# without a filesystem rather than dying when it does. This disk is a 256 MiB sparse
# file of zeros, so a refusal here means the "blank is claimable" rule regressed --
# and it must fail this gate rather than let it pass on a server that answers
# FAILED_PRECONDITION to everything. Checked BEFORE the LISTENING needle: a degraded
# server still listens, and -DEGRADED is always emitted first.
DEGRADED = "CERISE-FILESERVER-DEGRADED"
# the fileserver acquires its address via REAL DHCPv4 DORA over a
# fuchsia.posix.socket.packet socket (slirp's built-in bootp server offers
# 10.0.2.15/24) and brings up a v6 SLAAC link-local — both BEFORE it mounts fxfs
# and starts listening, so these must be present the moment LISTENING appears.
DHCP_LEASE = "CERISE-DHCP-LEASE=10.0.2.15/24"
DHCP_FAIL = "CERISE-DHCP-FAIL"
SLAAC_OK = "CERISE-SLAAC-ADDR-OK"
BOOT_TIMEOUT_S = 600.0
FT_FILE, FT_DIR = 1, 2
GRPC_NOT_FOUND = 5
PAYLOAD = b"hello cerise fxfs e2e\n"


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_e2e(port):
    c = GrpcConn("127.0.0.1", port)
    try:
        # 1. Write hello.txt
        msg, st, _ = c.call(SVC + "/Write",
                            pb_str(1, "hello.txt") + pb_uint(2, 0) + pb_bytes(3, PAYLOAD)
                            + pb_bool(4, True) + pb_bool(5, True))
        assert st == 0, f"Write status {st}"
        n = pb_decode(msg[0]).get(1, 0)
        assert n == len(PAYLOAD), f"Write bytes_written {n} != {len(PAYLOAD)}"
        print(f"[e2e] Write hello.txt = {len(PAYLOAD)} bytes: {PAYLOAD!r}", flush=True)

        # 2. Read back
        msgs, st, _ = c.call(SVC + "/Read", pb_str(1, "hello.txt") + pb_uint(2, 0)
                            + pb_uint(3, len(PAYLOAD)),
                            streaming=True)
        assert st == 0, f"Read status {st}"
        got = b"".join(pb_decode(m).get(1, b"") for m in msgs)
        assert got == PAYLOAD, f"Read mismatch: {got!r} != {PAYLOAD!r}"
        print(f"[e2e] Read hello.txt back: {got!r}  MATCH", flush=True)

        # 3. Stat size
        msg, st, _ = c.call(SVC + "/Stat", pb_str(1, "hello.txt"))
        assert st == 0, f"Stat status {st}"
        f = pb_decode(msg[0])
        assert f.get(1) == FT_FILE and f.get(2) == len(PAYLOAD), f"Stat {f}"
        print(f"[e2e] Stat hello.txt: type=FILE size={f.get(2)}", flush=True)

        # 4. List root shows hello.txt
        msgs, st, _ = c.call(SVC + "/List", pb_str(1, ""), streaming=True)
        assert st == 0, f"List status {st}"
        names = [pb_decode(m).get(1, b"").decode() for m in msgs]
        assert "hello.txt" in names, f"List missing hello.txt: {names}"
        print(f"[e2e] List root: {names}", flush=True)

        # 5. Mkdir d
        _, st, _ = c.call(SVC + "/Mkdir", pb_str(1, "d") + pb_bool(2, False))
        assert st == 0, f"Mkdir status {st}"
        print("[e2e] Mkdir d", flush=True)

        # 6. Rename hello.txt -> d/renamed.txt
        _, st, _ = c.call(SVC + "/Rename", pb_str(1, "hello.txt") + pb_str(2, "d/renamed.txt"))
        assert st == 0, f"Rename status {st}"
        print("[e2e] Rename hello.txt -> d/renamed.txt", flush=True)

        # 7. Stat new path (size matches), old path NOT_FOUND
        msg, st, _ = c.call(SVC + "/Stat", pb_str(1, "d/renamed.txt"))
        assert st == 0 and pb_decode(msg[0]).get(2) == len(PAYLOAD), f"Stat renamed {st} {msg}"
        _, st, _ = c.call(SVC + "/Stat", pb_str(1, "hello.txt"))
        assert st == GRPC_NOT_FOUND, f"expected NOT_FOUND for old path, got {st}"
        print(f"[e2e] Stat d/renamed.txt OK; Stat hello.txt -> NOT_FOUND ({st})", flush=True)

        # 8. Delete, then Read -> NOT_FOUND
        _, st, _ = c.call(SVC + "/Delete", pb_str(1, "d/renamed.txt") + pb_bool(2, False))
        assert st == 0, f"Delete status {st}"
        _, st, _ = c.call(SVC + "/Read", pb_str(1, "d/renamed.txt") + pb_uint(2, 0)
                          + pb_uint(3, 1),
                          streaming=True)
        assert st == GRPC_NOT_FOUND, f"expected NOT_FOUND after delete, got {st}"
        print(f"[e2e] Delete d/renamed.txt; Read -> NOT_FOUND ({st})", flush=True)

        # 9. Recursive delete: a non-empty directory must be removed with recursive=true.
        _, st, _ = c.call(SVC + "/Mkdir", pb_str(1, "rd") + pb_bool(2, False))
        assert st == 0, f"Mkdir rd {st}"
        _, st, _ = c.call(SVC + "/Write",
                          pb_str(1, "rd/inner.txt") + pb_uint(2, 0) + pb_bytes(3, b"inner")
                          + pb_bool(4, True) + pb_bool(5, True))
        assert st == 0, f"Write rd/inner.txt {st}"
        # non-recursive delete of a non-empty dir must fail (FAILED_PRECONDITION=9)
        _, st, _ = c.call(SVC + "/Delete", pb_str(1, "rd") + pb_bool(2, False))
        assert st == 9, f"expected FAILED_PRECONDITION for non-recursive rmdir, got {st}"
        _, st, _ = c.call(SVC + "/Delete", pb_str(1, "rd") + pb_bool(2, True))
        assert st == 0, f"recursive Delete rd {st}"
        _, st, _ = c.call(SVC + "/Stat", pb_str(1, "rd"))
        assert st == GRPC_NOT_FOUND, f"rd should be gone, got {st}"
        print(f"[e2e] Recursive Delete rd/ (with inner.txt): gone (NOT_FOUND {st})", flush=True)

        # 10. Multi-chunk Read: a >64KB file must stream back in multiple ReadChunks.
        pattern = bytes((i * 37 + 11) % 251 for i in range(200 * 1024))  # 200 KiB
        off = 0
        while off < len(pattern):  # write in <=32KB slices (bounded WriteRequest)
            end = min(off + 32 * 1024, len(pattern))
            _, st, _ = c.call(SVC + "/Write",
                              pb_str(1, "big.bin") + pb_uint(2, off) + pb_bytes(3, pattern[off:end])
                              + pb_bool(4, off == 0) + pb_bool(5, off == 0))
            assert st == 0, f"Write big.bin@{off} {st}"
            off = end
        msgs, st, _ = c.call(SVC + "/Read", pb_str(1, "big.bin") + pb_uint(2, 0)
                            + pb_uint(3, len(pattern)),
                            streaming=True)
        assert st == 0, f"Read big.bin {st}"
        big = b"".join(pb_decode(m).get(1, b"") for m in msgs)
        assert big == pattern, f"big.bin mismatch: {len(big)} vs {len(pattern)}"
        assert len(msgs) >= 3, f"expected multiple ReadChunks for 200KB, got {len(msgs)}"
        print(f"[e2e] Multi-chunk Read big.bin: {len(big)} bytes in {len(msgs)} chunks  MATCH",
              flush=True)

        # sentinel -> guest emits CERISE-FILESERVER-E2E-OK
        c.call(SVC + "/Stat", pb_str(1, "__cerise_e2e_ok__"))
    finally:
        c.close()


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
    serial = tmp / "fileserver-serial.log"
    if serial.exists():
        serial.unlink()
    nvme = tmp / "fxfs-nvme.img"
    with open(nvme, "wb") as f:  # 256 MiB blank NVMe scratch disk for fxfs
        f.truncate(256 * 1024 * 1024)
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
    print(f"[e2e] booting fileserver+fxfs; hostfwd 127.0.0.1:{port} -> guest:50051", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        deadline = time.time() + BOOT_TIMEOUT_S
        while time.time() < deadline:
            txt = serial.read_text(errors="replace") if serial.exists() else ""
            # ALL failure markers are tested before the success needle. The guest
            # can emit a failure and then still reach LISTENING (a degraded file
            # server serves), so needle-first would let such a boot pass.
            if DEGRADED in txt:
                tail = txt[txt.rfind(DEGRADED):][:400]
                raise AssertionError(f"file server refused this BLANK disk: {tail}")
            if FAIL in txt or DHCP_FAIL in txt:
                marker = DHCP_FAIL if DHCP_FAIL in txt else FAIL
                tail = txt[txt.rfind(marker):][:300]
                raise AssertionError(f"guest failure marker: {tail}")
            if LISTENING in txt:
                break
            if proc.poll() is not None:
                raise AssertionError(f"QEMU exited early ({proc.returncode})")
            time.sleep(3)
        else:
            raise AssertionError("timed out waiting for CERISE-FILESERVER-LISTENING")
        # DHCP + SLAAC address acquisition must have happened before listening: the
        # gRPC reachability proof below then rides a DHCP-leased address, not a
        # hardcoded one.
        if DHCP_LEASE not in txt:
            raise AssertionError(
                f"reached {LISTENING} without {DHCP_LEASE} (DHCP DORA proof missing)")
        if SLAAC_OK not in txt:
            raise AssertionError(
                f"reached {LISTENING} without {SLAAC_OK} (SLAAC v6 proof missing)")
        print(f"[e2e] {DHCP_LEASE} + {SLAAC_OK} observed before {LISTENING}", flush=True)
        print(f"[e2e] {LISTENING} (fxfs mounted); running RPC sequence", flush=True)

        run_e2e(port)

        # confirm the guest observed the completed sequence
        deadline = time.time() + 20
        while time.time() < deadline:
            if "CERISE-FILESERVER-E2E-OK" in serial.read_text(errors="replace"):
                break
            time.sleep(1)
        else:
            raise AssertionError("guest CERISE-FILESERVER-E2E-OK not observed")
        print("[e2e] PASS: real files round-tripped over gRPC/netstack3/fxfs; "
              "guest emitted CERISE-FILESERVER-E2E-OK", flush=True)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
