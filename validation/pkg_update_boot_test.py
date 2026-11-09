#!/usr/bin/env python3
"""Cerise packages: the flagship UPDATABLE-packages boot gate.

Boots //products:qemu-x64-pkg-update TWICE against the SAME NVMe image, with a virtio-net NIC and a
host-side plain-HTTP server (127.0.0.1:52099) that serves version 2 of the demo package. The guest
reaches the host at 10.0.2.2 (QEMU SLIRP host alias) — outbound, no hostfwd/guestfwd needed.

  BOOT 1 (blank disk, empty dynamic index): provision -> fshost mount -> pkg_fetcher ingests the BASE
    package v1 and launches it from the BOOTFS BASE index (CERISE-PKG-UPDATE-V1-LAUNCHED) -> brings up
    netstack3 + DHCP -> DOWNLOADS v2 over the network, MERKLE-VERIFIES + installs it
    (CERISE-PKG-UPDATE-FETCH-OK) -> REGISTERS v2 in the PERSISTENT dynamic index (CERISE-PKG-UPDATE-REGISTERED)
    -> launches v2 from the dynamic index, which SHADOWS base (CERISE-PKG-UPDATE-V2-LAUNCHED) -> the
    verified-exec identity NEGATIVE (a lying index entry is rejected: CERISE-PKG-UPDATE-IDENTITY-REJECT).
    The host server records >0 requests (the fetch happened).

  BOOT 2 (SAME disk, dynamic index + v2 blobs persisted): pkg_fetcher sees v2 already registered,
    SKIPS the network entirely (CERISE-PKG-UPDATE-SKIP-FETCH), and launches v2 from the PERSISTENT dynamic
    index (CERISE-PKG-UPDATE-V2-LAUNCHED). The host server records ZERO requests on boot 2 — the
    NOT-REFETCHED proof: the update survived a reboot with no network access.

Proves: a persistent, updatable package index; real network package delivery with pre-install
merkle verification; dynamic-shadows-base resolution; verified-exec identity binding; and durability
of the update across reboot without re-fetch.
"""
from __future__ import annotations
import argparse, http.server, json, os, pathlib, socketserver, subprocess, sys, threading, time

HTTP_PORT = 52099  # must match pkg_fetcher's HOST_ADDR (10.0.2.2:52099)
SUCCESS = "CERISE-PKG-UPDATE-OK"
FAIL_MARKERS = ["CERISE-PKG-UPDATE-FETCHER-FAIL", "CERISE-PKG-RESOLVER-FAIL", "CERISE-PKG-RESOLVER-RESOLVE-FAIL",
                "CERISE-PROVISION-FAIL", "CERISE-DHCP-FAIL"]
FORBIDDEN = ["panic", "triple fault", "KERNEL FAULT", "FATAL ERROR"]
BOOT_TIMEOUT_S = 240.0


def _need(p, what):
    if not p or not os.path.exists(p):
        raise SystemExit(f"{what} not found: {p}")
    return p


# ---------------------------------------------------------------------------------------------
# Host-side v2 package server (plain HTTP/1). Serves /manifest.json + /blob/<merkle>, and COUNTS
# requests so boot 2 can prove the guest did not re-fetch.
# ---------------------------------------------------------------------------------------------
class V2Store:
    def __init__(self, v2_dir: pathlib.Path):
        self.manifest_bytes = (v2_dir / "manifest.json").read_bytes()
        manifest = json.loads(self.manifest_bytes)
        # merkle -> raw bytes, for the meta.far and every content blob (by runtime_path blobs/blob_i).
        self.by_merkle: dict[str, bytes] = {}
        self.by_merkle[manifest["meta_far"]["merkle"]] = (v2_dir / "meta.far").read_bytes()
        for entry in manifest["blobs"]:
            rp = entry["runtime_path"]           # "blobs/blob_<i>"
            fname = rp.split("/")[-1]             # "blob_<i>"
            self.by_merkle[entry["merkle"]] = (v2_dir / fname).read_bytes()
        # (signed index): the signed dynamic-index entries the fetcher downloads. /entry.json is
        # the genuine signed v2 entry; /entry_bad.json has a corrupted signature (the SIG negative);
        # /entry_evil.json is a validly-signed but lying-identity entry (the identity negative).
        self.entry_json = (v2_dir / "entry.json").read_bytes()
        self.entry_bad_json = (v2_dir / "entry_bad.json").read_bytes()
        self.entry_evil_json = (v2_dir / "entry_evil.json").read_bytes()
        self.request_count = 0
        self.lock = threading.Lock()


def make_handler(store: V2Store):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence
            pass

        def _send(self, body: bytes, status=200):
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            with store.lock:
                store.request_count += 1
            if self.path == "/manifest.json":
                self._send(store.manifest_bytes)
            elif self.path == "/entry.json":
                self._send(store.entry_json)
            elif self.path == "/entry_bad.json":
                self._send(store.entry_bad_json)
            elif self.path == "/entry_evil.json":
                self._send(store.entry_evil_json)
            elif self.path.startswith("/blob/"):
                merkle = self.path[len("/blob/"):]
                body = store.by_merkle.get(merkle)
                if body is None:
                    self._send(b"unknown blob\n", status=404)
                else:
                    self._send(body)
            else:
                self._send(b"not found\n", status=404)

    return Handler


class ReusableServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def boot(qemu, shim, zbi, datadir, nvme, serial, ordered, require_absent=None):
    if serial.exists():
        serial.unlink()
    cmd = [qemu, "-L", datadir, "-machine", "q35", "-nographic", "-monitor", "none",
           "-no-reboot", "-m", "4096M",
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-netdev", "user,id=net0",
           "-device", "virtio-net-pci,disable-legacy=on,netdev=net0,romfile=",
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
            break
        for fm in FAIL_MARKERS:
            if fm in txt:
                proc.terminate()
                raise AssertionError(f"guest failure ({fm}):\n{txt[txt.rfind(fm):][:700]}")
        for fb in FORBIDDEN:
            if fb in txt:
                proc.terminate()
                raise AssertionError(f"forbidden marker ({fb}):\n{txt[txt.rfind(fb):][:700]}")
        if proc.poll() is not None:
            raise AssertionError(f"QEMU exited early ({proc.returncode})\n{txt[-1000:]}")
        time.sleep(3)
    else:
        proc.terminate()
        raise AssertionError(f"timed out waiting for {SUCCESS}\n{txt[-1800:]}")
    # Ordered-marker check.
    last = -1
    for m in ordered:
        i = txt.find(m)
        assert i != -1, f"missing required marker: {m}\n--- tail ---\n{txt[-1800:]}"
        assert i > last, f"marker out of order: {m}"
        last = i
    for m in (require_absent or []):
        assert m not in txt, f"marker unexpectedly present: {m}"
    for fb in FORBIDDEN:
        assert fb not in txt, f"forbidden marker present: {fb}"
    return proc, txt


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
    ap.add_argument("--v2-dir", required=True, help="dir with v2 manifest.json + meta.far + blob_<i>")
    ns = ap.parse_args()
    qemu, shim = _need(ns.qemu, "qemu"), _need(ns.shim, "shim")
    zbi, datadir = _need(ns.zbi, "zbi"), _need(ns.qemu_data_dir, "qemu data dir")
    v2_dir = pathlib.Path(_need(ns.v2_dir, "v2 dir"))

    # Start the host-side v2 package server.
    store = V2Store(v2_dir)
    httpd = ReusableServer(("127.0.0.1", HTTP_PORT), make_handler(store))
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    print(f"[pkg-update] host v2 server on 127.0.0.1:{HTTP_PORT} "
          f"({len(store.by_merkle)} blobs); guest reaches it at 10.0.2.2:{HTTP_PORT}", flush=True)

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    nvme = tmp / "pkg-update-nvme.img"
    with open(nvme, "wb") as f:  # created ONCE, reused across BOTH boots
        f.truncate(256 * 1024 * 1024)

    try:
        # --- Boot 1: fresh disk -> v1 from base, fetch v2, register, v2 from dynamic ---
        t0 = time.time()
        boot1_ordered = [
            "CERISE-PROVISION-READY",
            "CERISE-PKG-UPDATE-FETCHER-READY",
            "CERISE-PKG-RESOLVER-PUBKEY-OK",  # resolver (Lazy) loaded the embedded ed25519 public key
            "CERISE-PKG-UPDATE-V1-LAUNCHED",       # v1 from the BOOTFS BASE index
            "CERISE-PKG-UPDATE-DHCP-LEASE=10.0.2.15/24",
            "CERISE-PKG-UPDATE-FETCH-OK",          # v2 downloaded + merkle-verified + installed
            "CERISE-PKG-SIGNATURE-OK",            # v2's SIGNED entry verified (ed25519 + counter)
            "CERISE-PKG-UPDATE-REGISTERED",        # v2 written to the persistent dynamic index
            "CERISE-PKG-UPDATE-SOURCE-DYNAMIC",    # resolver served v2 from the dynamic index
            "CERISE-PKG-UPDATE-V2-LAUNCHED",       # v2 ran (update took effect IN-BOOT)
            "CERISE-PKG-GC-VERIFIED",       # GC (post-update): v1's now-shadowed meta.far is GONE
            "CERISE-PKG-GC-KEPT",           # GC: v2 + shared libs survived (live data intact)
            "CERISE-PKG-SIGNATURE-REJECT",        # signed-index: a TAMPERED signed entry was rejected
            "CERISE-PKG-UPDATE-IDENTITY-REJECT",   # verified-exec: a lying (but signed) entry was rejected
            SUCCESS,
        ]
        with store.lock:
            store.request_count = 0
        proc, _ = boot(qemu, shim, zbi, datadir, nvme, tmp / "pkg-update-1.log", boot1_ordered)
        b1_requests = store.request_count
        stop(proc)
        assert b1_requests > 0, "boot 1 host server saw NO requests — v2 was not fetched over the network"
        print(f"[pkg-update] boot 1 ({time.time()-t0:.0f}s): v1 (base) -> fetch v2 ({b1_requests} host "
              f"requests) -> register -> v2 (dynamic) -> identity-reject. OK", flush=True)

        # --- Boot 2: SAME disk -> v2 from the PERSISTENT dynamic index, NO re-fetch ---
        t1 = time.time()
        boot2_ordered = [
            "CERISE-PROVISION-SKIP",         # provisioner idempotent (disk already Fxfs+blob)
            "CERISE-PKG-UPDATE-FETCHER-READY",
            "CERISE-PKG-UPDATE-SKIP-FETCH",        # dynamic index already has v2 -> skip network
            "CERISE-PKG-RESOLVER-PUBKEY-OK",  # resolver loaded the embedded pubkey
            # (SOURCE-DYNAMIC below is itself the proof the PERSISTED signature re-verified: filter_signed
            #  only keeps it if the ed25519 signature is still valid.)
            "CERISE-PKG-UPDATE-SOURCE-DYNAMIC",    # resolver served v2 from the PERSISTENT dynamic index
            "CERISE-PKG-UPDATE-V2-LAUNCHED",       # v2 ran again, from persisted blobs+index
            SUCCESS,
        ]
        with store.lock:
            store.request_count = 0
        proc, _ = boot(qemu, shim, zbi, datadir, nvme, tmp / "pkg-update-2.log", boot2_ordered,
                       require_absent=["CERISE-PKG-UPDATE-FETCH-OK", "CERISE-PKG-UPDATE-REGISTERED",
                                       "CERISE-PKG-GC-START"])  # GC is post-update only; not on skip-fetch boot
        b2_requests = store.request_count
        stop(proc)
        assert b2_requests == 0, \
            f"NOT-REFETCHED proof FAILED: host server saw {b2_requests} requests on boot 2 (expected 0)"
        print(f"[pkg-update] boot 2 ({time.time()-t1:.0f}s): v2 from PERSISTENT dynamic index, "
              f"{b2_requests} host requests (not re-fetched). OK", flush=True)
    finally:
        httpd.shutdown()

    print("[pkg-update] PASS: packages are updatable over the network, the update persists across "
          "reboot with no re-fetch, and verified-exec rejects a lying index entry.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
