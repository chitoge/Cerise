#!/usr/bin/env python3
"""Cerise post-mortem gate: userspace crash handler (root-job exception path).

Boots //products:qemu-x64-crash-handler via the direct-kernel path. The minimal
realm runs crash_handler (eager) — which obtains the narrowly-routed
fuchsia.kernel.RootJob and binds its exception channel — then launches the lazy
crasher via its Binder. The crasher null-derefs; with no closer handler the
exception reaches the root-job channel, where crash_handler logs it and emits a
self-contained symbolizer-markup block ({{{reset}}}/{{{module}}}/{{{mmap}}}/{{{bt}}})
before releasing it unhandled so the crasher still dies.

The gate asserts, IN ORDER, that crash_handler came up, the crasher ran, the
crash was observed with a fatal-page-fault exception + registers + a backtrace,
and the markup block is present. It THEN pipes the serial log through
//src/cerise/tools/symbolize against the crash-handler .build-id store and asserts
a REAL symbolized crasher frame (crasher::trigger_null_deref) — proving the
end-to-end "crash -> markup -> symbols" pipeline resolves an actual source frame.
"""
from __future__ import annotations
import argparse, os, pathlib, subprocess, sys, time

HANDLER_READY = "CERISE-CRASH-HANDLER-READY"
CRASHER_START = "CERISE-CRASHER-START"
CRASH_OBSERVED = "CERISE-CRASH: process"
CRASH_END = "CERISE-CRASH-END"
# A REAL crasher-module frame the backtrace must resolve to once symbolized.
# Frame 0 (the fault PC) resolves to the inlined `core::ptr::read_volatile` inside
# crasher::trigger_null_deref; the reliably-captured crasher frame is frame 1 —
# the return address into crasher::main (the call site), which resolves to this
# symbol with real crasher source (src/cerise/crasher/src/main.rs).
SYMBOL = "crasher::main"

# Ordered markers proving the whole exception path ran.
ORDERED_MARKERS = [
    HANDLER_READY,     # crash_handler attached to the root-job exception channel
    CRASHER_START,     # the lazy crasher was launched (post-attach) and ran
    CRASH_OBSERVED,    # crash_handler observed the crash (process/thread/type)
    "{{{bt:0:",        # ... and emitted a backtrace (frame 0 = fault PC)
    CRASH_END,         # ... and finished handling it
]

READY_TIMEOUT_S = 420.0    # boot -> crash_handler up + crasher crash observed
FAIL = "CERISE-CRASH-HANDLER-FAIL"
PANICS = ("ZIRCON KERNEL PANIC", "KERNEL PANIC", "triple fault", "KERNEL FAULT")


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def _read(serial: pathlib.Path) -> str:
    return serial.read_text(errors="replace") if serial.exists() else ""


def _check_no_fault(txt: str):
    if FAIL in txt:
        i = txt.find(FAIL)
        raise AssertionError(f"crash_handler reported failure: {txt[i:i+300]!r}")
    for p in PANICS:
        if p in txt:
            i = txt.find(p)
            raise AssertionError(f"unexpected kernel fault/panic on serial: {txt[i:i+300]!r}")


def _wait_for(serial, needle, timeout_s, proc):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        txt = _read(serial)
        _check_no_fault(txt)
        if needle in txt:
            return txt
        if proc.poll() is not None:
            raise AssertionError(
                f"QEMU exited (rc={proc.returncode}) before {needle!r} appeared")
        time.sleep(2)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {needle!r}")


def _assert_ordered(txt: str, markers):
    last = -1
    for m in markers:
        i = txt.find(m, last + 1)
        if i < 0:
            raise AssertionError(f"missing expected chain marker {m!r} on serial")
        if i <= last:
            raise AssertionError(f"chain marker {m!r} out of order on serial")
        last = i


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--shim", required=True)
    ap.add_argument("--zbi", required=True)
    ap.add_argument("--qemu-data-dir", required=True)
    ap.add_argument("--symbolize", required=True)
    ap.add_argument("--build-id-dir", required=True)
    ap.add_argument("--llvm-symbolizer", required=True)
    ns = ap.parse_args()
    qemu = _need(ns.qemu, "qemu")
    shim = _need(ns.shim, "shim")
    zbi = _need(ns.zbi, "zbi")
    datadir = _need(ns.qemu_data_dir, "qemu data dir")
    symbolize = _need(ns.symbolize, "symbolize tool")
    store = _need(ns.build_id_dir, "build-id store")
    llvm_symbolizer = _need(ns.llvm_symbolizer, "llvm-symbolizer")

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    outdir = pathlib.Path(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR", str(tmp)))
    outdir.mkdir(parents=True, exist_ok=True)
    serial = outdir / "crash-handler-serial.log"
    if serial.exists():
        serial.unlink()

    # -no-reboot: the crasher dies (its crash is released unhandled) but the system
    # stays up (a child-process death is not a reboot); if anything DID reset, this
    # exits QEMU and the wait fails loudly rather than hanging.
    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot", "-m", "2048M",
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-kernel", shim, "-initrd", zbi]
    print("[crash-handler] booting qemu-x64-crash-handler (direct-kernel)", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        _wait_for(serial, CRASH_END, READY_TIMEOUT_S, proc)
        txt = _read(serial)
        _assert_ordered(txt, ORDERED_MARKERS)
        print("[crash-handler] crash observed + markup emitted; symbolizing", flush=True)
    except (AssertionError, SystemExit):
        # on ANY failure (timeout, missing marker, panic) end with the
        # symbolized serial tail so the captured markup reads as named frames, not hex
        # — not just on the later SYMBOL-not-found path.
        try:
            env = dict(os.environ, CERISE_LLVM_SYMBOLIZER=llvm_symbolizer)
            sym = subprocess.run(
                [symbolize, "--build-id-dir", store, "--llvm-symbolizer", llvm_symbolizer, str(serial)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                env=env, check=False,
            )
            if sym.returncode == 0 and sym.stdout:
                tail = "\n".join(sym.stdout.splitlines()[-60:])
                print("[crash-handler] FAILURE — symbolized serial tail:\n" + tail,
                      file=sys.stderr, flush=True)
        except Exception:
            pass
        raise
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    # Host-side: resolve the emitted markup against the crash-handler .build-id store.
    env = dict(os.environ, CERISE_LLVM_SYMBOLIZER=llvm_symbolizer)
    out = subprocess.run(
        [symbolize, "--build-id-dir", store, "--llvm-symbolizer", llvm_symbolizer, str(serial)],
        capture_output=True, text=True, env=env,
    )
    if out.returncode != 0:
        raise AssertionError(f"symbolize failed (rc={out.returncode}): {out.stderr[:500]}")
    if SYMBOL not in out.stdout:
        # Show the symbolized frames to aid debugging.
        frames = "\n".join(l for l in out.stdout.splitlines() if "#" in l or "bt:" in l)[:2000]
        raise AssertionError(
            f"symbolized log did not name the crasher frame {SYMBOL!r}; frames:\n{frames}")

    print(f"[crash-handler] PASS: real userspace crash observed on the root-job "
          f"exception channel, markup emitted, and symbolized to a real crasher "
          f"frame ({SYMBOL})", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
