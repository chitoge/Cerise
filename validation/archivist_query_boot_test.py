#!/usr/bin/env python3
"""Cerise logging bring-up: Archivist ArchiveAccessor query proof.

Boots //products:qemu-x64-diagnostics via the direct-kernel path (the same
-kernel/-initrd recipe the other Cerise QEMU products use). The guest realm
root_dfv2acpi_diagnostics runs the vendored Archivist as a real CMv2 component and
the archivist_reader component, which:

  1. emits a known structured record (severity=Info, tag=cerise_archivist_probe, a
     distinctive needle message) through fuchsia.logger.LogSink — offered from the
     Archivist, which ingests it via the capability_requested event stream; then
  2. reads it back over fuchsia.diagnostics.ArchiveAccessor (routed out of the
     Archivist's diagnostics-accessors dictionary) using the diagnostics_reader
     client, asserting severity AND tag, and emits CERISE-ARCHIVIST-QUERY-OK.

This harness asserts that CERISE-ARCHIVIST-QUERY-OK reaches serial — i.e. a real
ArchiveAccessor round-trip returned the logged record. It fails on the reader's
distinct failure markers or on an early QEMU exit.
"""
from __future__ import annotations
import argparse, os, pathlib, subprocess, sys, time

OK = "CERISE-ARCHIVIST-QUERY-OK"
FAIL = "CERISE-ARCHIVIST-QUERY-FAIL"
MISMATCH = "CERISE-ARCHIVIST-QUERY-MISMATCH"
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
    serial = tmp / "archivist-query-serial.log"
    if serial.exists():
        serial.unlink()

    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot", "-m", "4096M",
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-kernel", shim, "-initrd", zbi]
    print("[diag] booting qemu-x64-diagnostics (Archivist + archivist_reader)",
          flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        deadline = time.time() + BOOT_TIMEOUT_S
        while time.time() < deadline:
            txt = serial.read_text(errors="replace") if serial.exists() else ""
            if OK in txt:
                print(f"[diag] PASS: observed {OK} on serial — a real ArchiveAccessor "
                      f"query returned the logged record.", flush=True)
                return 0
            if FAIL in txt:
                tail = txt[txt.rfind(FAIL):][:400]
                raise AssertionError(f"archivist query failed: {tail}")
            if MISMATCH in txt:
                tail = txt[txt.rfind(MISMATCH):][:400]
                raise AssertionError(f"archivist query returned mismatched record: {tail}")
            if proc.poll() is not None:
                tail = txt[-800:]
                raise AssertionError(
                    f"QEMU exited early ({proc.returncode}); serial tail:\n{tail}")
            time.sleep(3)
        else:
            tail = (serial.read_text(errors="replace")[-1200:]
                    if serial.exists() else "")
            raise AssertionError(f"timed out waiting for {OK}; serial tail:\n{tail}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
