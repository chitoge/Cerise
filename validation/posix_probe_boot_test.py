#!/usr/bin/env python3
"""Cerise: plain-C POSIX probe boot gate.

Boots //products:qemu-x64-diagnostics via the direct-kernel path. The guest
realm root_dfv2acpi_diagnostics runs posix_probe — a PLAIN C component linking
only the default sysroot (libc + libzircon + the runtime libfdio.so; NO static
fdio) — which:

  1. open()/read()/close()s /pkg/data/probe.txt through the loaded real
     libfdio.so and, on a content match, emits CERISE-POSIX-PROBE-IO-OK via
     zx_debug_write (direct serial; independent of stdout wiring); then
  2. printf()s a distinctive needle — musl stdio -> writev(1) -> libfdio.so ->
     the fd1 zx socket elf_runner installed -> fuchsia.logger.LogSink (the
     Archivist). archivist_reader queries that record back over
     fuchsia.diagnostics.ArchiveAccessor (asserting message AND moniker) and
     emits CERISE-POSIX-PROBE-OK.

This harness asserts BOTH markers reach serial: IO-OK proves the POSIX file API
works out of the box for plain C, and PROBE-OK proves the printf/stdio path end
to end. It fails fast on any CERISE-POSIX-PROBE-FAIL marker or early QEMU exit.
"""
from __future__ import annotations
import argparse, os, pathlib, subprocess, sys, time

IO_OK = "CERISE-POSIX-PROBE-IO-OK"
OK = "CERISE-POSIX-PROBE-OK"
FAIL = "CERISE-POSIX-PROBE-FAIL"
BOOT_TIMEOUT_S = 600.0


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


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
    serial = tmp / "posix-probe-serial.log"
    if serial.exists():
        serial.unlink()

    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot", "-m", "4096M",
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-kernel", shim, "-initrd", zbi]
    print("[posix] booting qemu-x64-diagnostics (posix_probe + archivist relay)",
          flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        deadline = time.time() + BOOT_TIMEOUT_S
        while time.time() < deadline:
            txt = serial.read_text(errors="replace") if serial.exists() else ""
            if FAIL in txt:
                tail = txt[txt.rfind(FAIL):][:400]
                raise AssertionError(f"posix probe failed: {tail}")
            if IO_OK in txt and OK in txt:
                print(f"[posix] PASS: observed {IO_OK} (plain-C open/read via the "
                      f"runtime libfdio.so) and {OK} (printf -> fd1 socket -> "
                      f"LogSink -> Archivist -> ArchiveAccessor round-trip) on "
                      f"serial.", flush=True)
                return 0
            if proc.poll() is not None:
                tail = txt[-800:]
                raise AssertionError(
                    f"QEMU exited early ({proc.returncode}); serial tail:\n{tail}")
            time.sleep(3)
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        missing = [m for m in (IO_OK, OK) if m not in txt]
        raise AssertionError(
            f"timeout: markers not observed: {missing}; serial tail:\n{txt[-800:]}")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    sys.exit(main())
