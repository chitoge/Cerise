#!/usr/bin/env python3
"""Cerise packages (post-storage app tier): the fileserver-from-package boot gate.

Boots //products:qemu-x64-console-pkg with TWO NVMe disks (disk1 = fshost's package store; disk2 =
the fileserver's own fxfs) and a host-side plain-HTTP server (127.0.0.1:52098) serving the FILESERVER
PACKAGE (meta.far + content blobs). The 8.5 MB fileserver binary is NOT in bootfs — it is delivered
over the network on first boot.

  status_console renders immediately (no fileserver yet) -> apptier_fetcher owns the NIC (DHCP) and
  DOWNLOADS the fileserver package (CERISE-APPTIER-FETCH-OK), merkle-verifies + installs its blobs, and
  binds it -> #pkg_resolver resolves fuchsia-pkg://cerise/fileserver from the trusted-in-image BASE
  index and launches it from DISK blobs (CERISE-APPTIER-LAUNCHED) -> the fileserver SHARES
  apptier_fetcher's interface (CERISE-FILESERVER-NIC-SHARED), mounts its own fxfs on disk2, and serves
  gRPC (CERISE-FILESERVER-LISTENING). A host gRPC client then drives a real Write->Read round-trip over
  QEMU hostfwd; the host package server records >0 requests.

Proves: a REAL production component (the gRPC fileserver) runs from a network-fetched fuchsia-pkg
package instead of bootfs, comes up sharing the fetcher's NIC, mounts its own fxfs, and serves gRPC
end to end. (Reboot-persistence of the package with zero refetch is a documented next step — it needs
deterministic per-disk claiming so the package store and the fileserver's fxfs land on fixed disks.) (post-storage app tier).
"""
from __future__ import annotations
import argparse, http.server, json, os, pathlib, socketserver, subprocess, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from grpc_h2 import GrpcConn, pb_str, pb_bytes, pb_uint, pb_bool, pb_decode

HTTP_PORT = 52098   # must match apptier_fetcher's HOST_ADDR (10.0.2.2:52098)
GRPC_HOSTFWD = 50601
SVC = "/cerise.fileserver.v1.FileServer"
LISTENING = "CERISE-FILESERVER-LISTENING"
# CERISE-FILESERVER-DEGRADED: the file server refuses to format a disk it cannot prove is
# blank and then serves WITHOUT a filesystem, so it still emits LISTENING. Both disks here
# are fresh sparse files, so a refusal is a regression -- and it has to be a fail marker or
# this gate would wait for LISTENING and get it from a server that answers nothing.
FAIL_MARKERS = ["CERISE-APPTIER-FAIL", "CERISE-FILESERVER-FAIL", "CERISE-FILESERVER-DEGRADED",
                "CERISE-CONSOLE-FAIL",
                "CERISE-PROVISION-FAIL", "CERISE-PKG-RESOLVER-FAIL", "CERISE-PKG-RESOLVER-RESOLVE-FAIL"]
FORBIDDEN = ["panic", "triple fault", "KERNEL FAULT", "FATAL ERROR", "not exposed"]
BOOT_TIMEOUT_S = 280.0


def _need(p, what):
    if not p or not os.path.exists(p):
        raise SystemExit(f"{what} not found: {p}")
    return p


class PkgStore:
    """Serves /manifest.json + /blob/<merkle> for the fileserver package; counts requests."""
    def __init__(self, d: pathlib.Path):
        self.manifest_bytes = (d / "manifest.json").read_bytes()
        m = json.loads(self.manifest_bytes)
        self.by = {m["meta_far"]["merkle"]: (d / "meta.far").read_bytes()}
        for e in m["blobs"]:
            self.by[e["merkle"]] = (d / e["runtime_path"].split("/")[-1]).read_bytes()
        self.n = 0
        self.lock = threading.Lock()


def make_handler(store):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _s(self, b, st=200):
            self.send_response(st); self.send_header("Content-Length", str(len(b)))
            self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            with store.lock:
                store.n += 1
            if self.path == "/manifest.json":
                self._s(store.manifest_bytes)
            elif self.path.startswith("/blob/"):
                b = store.by.get(self.path[len("/blob/"):]); self._s(b if b else b"no", 200 if b else 404)
            else:
                self._s(b"no", 404)
    return H


class Reusable(socketserver.ThreadingTCPServer):
    allow_reuse_address = True; daemon_threads = True


def boot(qemu, shim, zbi, datadir, d1, d2, serial, ordered, require_absent=None):
    if serial.exists():
        serial.unlink()
    cmd = [qemu, "-L", datadir, "-machine", "q35", "-nographic", "-monitor", "none",
           "-no-reboot", "-m", "4096M",
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{GRPC_HOSTFWD}-:50051",
           "-device", "virtio-net-pci,disable-legacy=on,netdev=net0,romfile=",
           "-drive", f"file={d1},if=none,format=raw,id=nvm0", "-device", "nvme,drive=nvm0,serial=disk1",
           "-drive", f"file={d2},if=none,format=raw,id=nvm1", "-device", "nvme,drive=nvm1,serial=disk2",
           "-kernel", shim, "-initrd", zbi]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.time() + BOOT_TIMEOUT_S
    txt = ""
    while time.time() < deadline:
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        # Fail markers first: a degraded file server still emits LISTENING.
        for fm in FAIL_MARKERS + FORBIDDEN:
            if fm in txt:
                proc.terminate(); raise AssertionError(f"failure marker ({fm}):\n{txt[txt.rfind(fm)-100:txt.rfind(fm)+600]}")
        if LISTENING in txt:
            break
        if proc.poll() is not None:
            raise AssertionError(f"QEMU exited early ({proc.returncode})\n{txt[-1200:]}")
        time.sleep(3)
    else:
        proc.terminate(); raise AssertionError(f"timed out waiting for {LISTENING}\n{txt[-1800:]}")
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
    return proc


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


def grpc_roundtrip(tag: str):
    """A real gRPC Write->Read round-trip against the guest fileserver over hostfwd."""
    payload = f"cerise-apptier-{tag}".encode()
    for _ in range(20):  # the listener may need a moment after LISTENING prints
        try:
            c = GrpcConn("127.0.0.1", GRPC_HOSTFWD)
            break
        except OSError:
            time.sleep(1)
    else:
        raise AssertionError("could not connect to guest gRPC port")
    try:
        _, st, _ = c.call(SVC + "/Write", pb_str(1, "a.txt") + pb_uint(2, 0) + pb_bytes(3, payload)
                          + pb_bool(4, True) + pb_bool(5, True))  # create + truncate
        assert st == 0, f"Write grpc-status {st}"
        msgs, st, _ = c.call(SVC + "/Read", pb_str(1, "a.txt") + pb_uint(2, 0)
                             + pb_uint(3, len(payload)), streaming=True)
        assert st == 0, f"Read grpc-status {st}"
        got = b"".join(pb_decode(m).get(1, b"") for m in msgs)
        assert got == payload, f"Read mismatch: {got!r} != {payload!r}"
    finally:
        c.close()
    print(f"[apptier] gRPC Write->Read round-trip OK ({tag}): {payload!r}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True); ap.add_argument("--shim", required=True)
    ap.add_argument("--zbi", required=True); ap.add_argument("--qemu-data-dir", required=True)
    ap.add_argument("--pkg-dir", required=True, help="dir with manifest.json + meta.far + blob_<i>")
    ns = ap.parse_args()
    qemu, shim = _need(ns.qemu, "qemu"), _need(ns.shim, "shim")
    zbi, datadir = _need(ns.zbi, "zbi"), _need(ns.qemu_data_dir, "qemu data dir")
    pkg_dir = pathlib.Path(_need(ns.pkg_dir, "pkg dir"))

    store = PkgStore(pkg_dir)
    httpd = Reusable(("127.0.0.1", HTTP_PORT), make_handler(store))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"[apptier] host fileserver-package server :{HTTP_PORT} ({len(store.by)} blobs)", flush=True)

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    d1, d2 = tmp / "apptier-nvme1.img", tmp / "apptier-nvme2.img"
    with open(d1, "wb") as f: f.truncate(256 * 1024 * 1024)   # fshost package store
    with open(d2, "wb") as f: f.truncate(128 * 1024 * 1024)   # fileserver's own fxfs

    try:
        # Boot: blank disks -> apptier_fetcher downloads the fileserver PACKAGE over the network ->
        # #pkg_resolver launches it from disk blobs -> the fileserver shares the NIC + mounts fxfs +
        # serves gRPC. A host gRPC client then drives a real Write->Read round-trip.
        t0 = time.time()
        # CERISE-FILESERVER-DISK-NOT-OURS then -FXFS-FORMATTED is the load-bearing pair, and
        # this is the only gate that can assert it. Two disks, one aggregated block service,
        # and both fshost and the fileserver enumerate it: the fileserver necessarily meets
        # the disk fshost's package store lives on. It must DECLINE that disk (its Fxfs has no
        # "default" volume, so it is not ours) and claim the other, blank one instead.
        #
        # This used to be the reverse of a passing test: with format-if-needed, landing on
        # fshost's disk simply reformatted fshost's package store and the gate went green
        # anyway. Asserting both markers, in order, is what stops that regressing quietly.
        # (Which physical disk is which is NOT asserted -- observed here, fshost takes the
        # 128 MiB one, i.e. the opposite of the d1/d2 comments below. The invariant is that
        # they end up on DIFFERENT disks, not on particular ones.)
        ordered = ["CERISE-CONSOLE-RENDERED", "CERISE-APPTIER-FETCHER-READY", "CERISE-APPTIER-DHCP-LEASE",
                   "CERISE-APPTIER-FETCH-OK", "CERISE-APPTIER-LAUNCHED", "CERISE-PKG-RESOLVER-RESOLVED",
                   "CERISE-FILESERVER-NIC-SHARED", "CERISE-FILESERVER-DISK-NOT-OURS",
                   "CERISE-FILESERVER-FXFS-FORMATTED", LISTENING]
        with store.lock: store.n = 0
        proc = boot(qemu, shim, zbi, datadir, d1, d2, tmp / "apptier-1.log", ordered)
        grpc_roundtrip("boot")
        n = store.n; stop(proc)
        assert n > 0, "host server saw NO requests — the fileserver package was not fetched"
        print(f"[apptier] ({time.time()-t0:.0f}s): console renders -> fetch fileserver pkg ({n} host "
              f"requests) -> launch from disk -> NIC-shared -> LISTENING -> gRPC Write/Read OK", flush=True)
    finally:
        httpd.shutdown()

    print("[apptier] PASS: a real production component (the 8.5 MB gRPC fileserver) runs from a "
          "network-fetched fuchsia-pkg package instead of bootfs, and serves gRPC end to end.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
