#!/usr/bin/env python3
"""Cerise: runtime-conformance boot gate.

Boots //products:qemu-x64-conformance via the direct-kernel path. The guest realm
root_dfv2acpi_conformance runs three independent eager probe components — a plain-C
probe (conformance_c), a C++ probe (conformance_cxx), and a Rust probe
(conformance_rust) — that EXERCISE and ASSERT, on a real boot, the libc / threads /
C++ / Rust runtime surface previously marked "should-work-unproven":

  * C:   pthreads/futex contention + condvar handoff (N=4), math, string/mem,
         setjmp/longjmp (incl. _setjmp/_longjmp), buffered stdio, a LogSink printf.
  * C++: throw/catch/rethrow + catch-by-base ACROSS a shared-library boundary
         (throw in libconfthrow.so, caught in the main binary — the acid test for
         the unwinder + eh_frame registration across a DT_NEEDED object), an
         exception thrown+caught in a std::thread, in-process __cxa_demangle,
         <random> (mt19937 + binomial_distribution), <filesystem> dir iteration.
  * Rust: std::thread (N>2) + channels, catch_unwind over a deliberate panic then
         continue, a multithreaded fuchsia_async SendExecutor (>=3 threads) running
         concurrent timers/tasks to completion, std::time, a panic backtrace.

Every pass/fail marker is written straight to serial via zx_debug_write, so the
gate never depends on the log pipeline. The three probes start concurrently, so
their markers INTERLEAVE nondeterministically; this harness therefore asserts, per
probe, that its markers appear as an ordered SUBSEQUENCE (not a global total order)
and that a terminal -DONE marker is reached. It fails fast on any CERISE-CONF-*-FAIL
marker, on a genuine panic/fault (the deliberate Rust panic is suppressed by the
probe's own panic hook, so it never reaches serial), or on an early QEMU exit.
"""
from __future__ import annotations
import argparse, os, pathlib, re, subprocess, sys, time

# Per-probe ordered marker subsequences. Each probe's markers must appear in this
# order relative to each other; different probes' markers may interleave freely.
PROBES = {
    "C": [
        "CERISE-CONF-C-START",
        "CERISE-CONF-C-THREADS-OK",
        "CERISE-CONF-C-MATH-OK",
        "CERISE-CONF-C-STRING-OK",
        "CERISE-CONF-C-SETJMP-OK",
        "CERISE-CONF-C-STDIO-OK",
        "CERISE-CONF-C-LOGSINK-OK",
        "CERISE-CONF-C-DONE",
    ],
    "CXX": [
        "CERISE-CONF-CXX-START",
        "CERISE-CONF-CXX-THROW-SO-OK",
        "CERISE-CONF-CXX-THREAD-EXC-OK",
        "CERISE-CONF-CXX-DEMANGLE-OK",
        "CERISE-CONF-CXX-RANDOM-OK",
        "CERISE-CONF-CXX-FS-OK",
        "CERISE-CONF-CXX-DONE",
    ],
    "RUST": [
        "CERISE-CONF-RUST-START",
        "CERISE-CONF-RUST-THREADS-OK",
        "CERISE-CONF-RUST-CATCH-UNWIND-OK",
        "CERISE-CONF-RUST-BACKTRACE-OK",
        "CERISE-CONF-RUST-SENDEXEC-OK",
        "CERISE-CONF-RUST-TIME-OK",
        "CERISE-CONF-RUST-DONE",
    ],
}

# Bring-up aid: CONF_PROBES=C,CXX restricts the gate to a subset of probes (used
# while adding probes one at a time). Unset / empty means all three (the gate).
_only = os.environ.get("CONF_PROBES", "").strip()
if _only:
    _keep = {p.strip().upper() for p in _only.split(",") if p.strip()}
    PROBES = {k: v for k, v in PROBES.items() if k in _keep}

FAIL_RE = re.compile(r"CERISE-CONF-\w+-FAIL[^\n]*")
# Real faults. NOTE: we deliberately do NOT match "panic" here — the Rust probe
# raises a deliberate panic caught by catch_unwind, and its panic hook suppresses
# the default output, but we keep the failure pattern scoped to hard faults so no
# stray "panic" token can trip the gate.
FAULT_RE = re.compile(r"(KERNEL PANIC|triple fault|KERNEL FAULT|ZIRCON KERNEL PANIC|caught fatal exception)")
BOOT_TIMEOUT_S = 480.0

DONE_MARKERS = [seq[-1] for seq in PROBES.values()]


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def _subsequence_ok(text, seq):
    """True iff every marker in seq appears in text in the given relative order."""
    pos = 0
    for m in seq:
        i = text.find(m, pos)
        if i < 0:
            return False
        pos = i + len(m)
    return True


def _missing_markers(text):
    miss = []
    for name, seq in PROBES.items():
        for m in seq:
            if m not in text:
                miss.append(m)
    return miss


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
    serial = tmp / "runtime-conformance-serial.log"
    if serial.exists():
        serial.unlink()

    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot", "-m", "4096M",
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-kernel", shim, "-initrd", zbi]
    print("[conf] booting qemu-x64-conformance (C / C++ / Rust runtime probes)",
          flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        deadline = time.time() + BOOT_TIMEOUT_S
        while time.time() < deadline:
            txt = serial.read_text(errors="replace") if serial.exists() else ""
            fail = FAIL_RE.search(txt)
            if fail:
                tail = txt[max(0, fail.start() - 200):fail.end() + 200]
                raise AssertionError(f"conformance probe FAIL marker: {fail.group(0)}\n"
                                     f"context:\n{tail}")
            fault = FAULT_RE.search(txt)
            if fault:
                raise AssertionError(f"guest fault: {fault.group(0)}\n"
                                     f"serial tail:\n{txt[-1200:]}")
            if all(d in txt for d in DONE_MARKERS):
                # All probes finished; assert each probe's ordered subsequence.
                for name, seq in PROBES.items():
                    if not _subsequence_ok(txt, seq):
                        raise AssertionError(
                            f"probe {name}: markers out of order or missing; "
                            f"expected subsequence {seq}\nserial tail:\n{txt[-1200:]}")
                print("[conf] PASS: all probes reached -DONE; per-probe ordered "
                      "subsequences verified:", flush=True)
                for name, seq in PROBES.items():
                    print(f"  {name}: {' -> '.join(seq)}", flush=True)
                return 0
            if proc.poll() is not None:
                raise AssertionError(
                    f"QEMU exited early ({proc.returncode}); missing "
                    f"{_missing_markers(txt)};\nserial tail:\n{txt[-1200:]}")
            time.sleep(3)
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        raise AssertionError(
            f"timeout: missing markers {_missing_markers(txt)};\n"
            f"serial tail:\n{txt[-1500:]}")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    sys.exit(main())
