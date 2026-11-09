#!/usr/bin/env python3
"""Cerise packages-foundation boot gate: a real package in the fxfs blob volume.

Boots //products:qemu-x64-pkg (root_dfv2acpi_pkg.cm) via the direct-kernel path with a SINGLE
fresh NVMe disk (a fresh image every run => a clean FIRST boot). Asserts, in order on serial:

  1. drivers bind (platform-bus/ACPI/PCI + the NVMe block driver),
  2. first-boot PROVISIONING: the fxfs_provisioner formats the virgin disk + creates the empty
     "blob" volume, then RELEASES it and serves its readiness gate
     (CERISE-PROVISION-FORMAT-OK -> CERISE-PROVISION-READY),
  3. the routed gate: pkg_probe observed the provisioner readiness
     (CERISE-PKG-PROBE-PROVISIONED-OBSERVED),
  4. INGEST: pkg_probe wrote the demo package's blobs (meta.far + content blobs) into fshost's
     fxfs "blob" volume via fuchsia.fxfs/BlobCreator, content-addressed + write-verified
     (CERISE-PKG-INGEST-OK),
  5. RESOLVE (package_directory over the fxfs blob volume):
       - meta/package read from the meta.far  (CERISE-PKG-MANIFEST-OK)
       - meta/pkg_hello.cm read + decoded as a real component manifest (CERISE-PKG-CM-OK)
       - the bin/pkg_hello CONTENT BLOB read back, merkle-verified (CERISE-PKG-BLOB-OK)
       - the package served as a live fuchsia.io directory, meta/package read through the
         served connection (CERISE-PKG-DIR-SERVED)
       - the bin/pkg_hello CONTENT blob read THROUGH the served directory — invoking
         NonMetaStorage::open (BlobReader -> vmo_blob -> StreamIoConnection), the
         de-stub — merkle-verified (CERISE-PKG-RESOLVER-CONTENT-SERVED)

with ZERO panics/faults and no *-FAIL marker. This is the storage+format layer of packages made
real: a genuine meta.far, content-addressed blobs in fxfs, merkle-verified reads
 adds: a content blob read THROUGH the served directory (CERISE-PKG-RESOLVER-CONTENT-SERVED),
and a REAL fuchsia-pkg:// resolve+LAUNCH — pkg_probe binds pkg_hello's Binder, component_manager
resolves fuchsia-pkg://cerise/pkg_hello via #pkg_resolver (serving the package dir EXECUTABLE from
the fxfs "blob" volume) and elf_runner starts pkg_hello with its binary + libs loaded from disk
blobs (CERISE-PKG-RESOLVER-LAUNCHED). NOT included (by design): OTA, pkg-cache, garbage collection, or
verified-exec policy.
"""
from __future__ import annotations
import argparse, os, pathlib, subprocess, sys, time

SUCCESS = "CERISE-PKG-OK"
ORDERED = [
    "CERISE-PLATFORM-BUS-OK",            # platform-bus/ACPI up
    "CERISE-PCI-ENUM",                   # PCI enumerated
    "CERISE-NVME-BOUND",                 # the block driver bound the disk
    "CERISE-PROVISION-FORMAT-OK",        # first-boot: virgin disk formatted as Fxfs
    "CERISE-PROVISION-BLOB-VOLUME-OK",   # first-boot: empty "blob" volume created
    "CERISE-PROVISION-READY",            # provisioner released the disk + serving the gate
    "CERISE-PKG-PROBE-PROVISIONED-OBSERVED",  # pkg_probe passed the routed gate
    "CERISE-PKG-INGEST-OK",              # blobs written into the fxfs "blob" volume via BlobCreator
    "CERISE-PKG-MANIFEST-OK",            # meta/package read from meta.far
    "CERISE-PKG-CM-OK",                  # meta/pkg_hello.cm read + decoded as a real manifest
    "CERISE-PKG-BLOB-OK",                # bin/pkg_hello content blob read back, merkle-verified
    "CERISE-PKG-DIR-SERVED",             # package served as a live fuchsia.io directory (meta/package read through it)
    "CERISE-PKG-RESOLVER-CONTENT-SERVED",        # bin/pkg_hello CONTENT blob read THROUGH the served dir (NonMetaStorage::open)
    "CERISE-PKG-RESOLVER-LAUNCHED",              # pkg_hello LAUNCHED by component_manager from a fuchsia-pkg:// URL (disk blobs)
    SUCCESS,
]
FAIL_MARKERS = ["CERISE-PKG-FAIL", "CERISE-PROVISION-FAIL", "CERISE-PKG-RESOLVER-FAIL", "CERISE-PKG-RESOLVER-RESOLVE-FAIL"]
# netdev_probe (inherited from the shared driver stack) exits 1 every boot here — this disk-only
# QEMU config has no NIC to bind — a benign component_manager WARN. It never touches the disk or
# the package path, so it is deliberately NOT a failure/forbidden marker.
FORBIDDEN = ["panic", "triple fault", "KERNEL FAULT", "FATAL ERROR"]
# NVMe bind (~180-200s on this host) dominates, then provision + fshost mount + blob ingest +
# package resolve. Bounded to stay under the gate's --test_timeout=520.
BOOT_TIMEOUT_S = 480.0


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
        if SUCCESS in txt:
            return proc, txt
        for fm in FAIL_MARKERS:
            if fm in txt:
                proc.terminate()
                raise AssertionError(f"guest failure ({fm}):\n{txt[txt.rfind(fm):][:600]}")
        for fb in FORBIDDEN:
            if fb in txt:
                proc.terminate()
                raise AssertionError(f"forbidden marker ({fb}):\n{txt[txt.rfind(fb):][:600]}")
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
    nvme = tmp / "pkg-nvme.img"
    with open(nvme, "wb") as f:  # fresh blank disk => a clean FIRST boot every run
        f.truncate(256 * 1024 * 1024)

    serial = tmp / "pkg-serial.log"
    t0 = time.time()
    proc, txt = boot(qemu, shim, zbi, datadir, nvme, serial)
    try:
        assert_ordered(txt)
        print(f"[pkg-boot] PASS in {time.time() - t0:.0f}s: provision -> fshost mount -> package "
              f"ingest (BlobCreator) -> package_directory resolve (meta.far + .cm + content blob "
              f"merkle-verified).", flush=True)
    finally:
        stop(proc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
