#!/usr/bin/env python3
"""Cerise status-console initial prototype live-boot proof: a driverless QEMU framebuffer.

Boots //products:qemu-x64-console-spike via the direct-kernel path (the same
-kernel/-initrd recipe the netstack-sized products use), adding a `-device VGA`
(QEMU stdvga, PCI 1234:1111) display and a QMP control channel. The guest fb_spike
component brings up the stdvga linear framebuffer with NO display driver — it drives
PCI config over CF8/CFC, sets a Bochs VBE mode, and maps the framebuffer BAR via
zx_vmo_create_physical — then paints a deterministic pattern and emits
CERISE-FBSPIKE-RENDERED. This harness then drives QMP `screendump` and saves the PPM
as an undeclared test output.

WHAT THE PIXEL ASSERTION PROVES. It used to be "the screendump is not one flat colour".
That is satisfied by a single stripe — and the whole residual risk this gate exists to
retire is "does a guest write to the BAR actually reach scanout", which one stripe does
not answer any better than a title bar answers "is the panel drawn".

It now requires the captured frame to be EXACTLY the frame fb_spike.rs paints: the mode,
the background, three bars in three named colours across three thirds of the bottom
third, and an amber panel with a background-coloured inset 16px inside it — every one of
the 786,432 pixels. The expectation is reconstructed from the guest's own source
(panel_check.expected_spike_frame), so the matcher cannot describe a picture nobody
draws, and a paint that changes fails loudly saying so rather than as a pixel diff.

The cheapest implementations that satisfied the old assertion — clear the screen to one
colour and draw one bar; get the mode set and paint nothing else; write the pattern at
the wrong stride — all fail this one. validation/framebuffer_assert_test.py builds those
frames and proves it.
"""
from __future__ import annotations
import argparse, json, os, pathlib, socket, subprocess, sys, time

import panel_check

RENDERED = "CERISE-FBSPIKE-RENDERED"
FAIL = "CERISE-FBSPIKE-FAIL"
BOOT_TIMEOUT_S = 600.0


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Qmp:
    """A minimal QMP client over TCP (connect -> qmp_capabilities -> ...).

    TCP (not a unix socket) deliberately: bazel's TEST_TMPDIR path easily exceeds the
    108-char AF_UNIX limit, which makes QEMU fail to bind and exit immediately.
    """

    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.f = self.sock.makefile("rwb", buffering=0)
        greeting = self._read()  # the QMP banner
        assert "QMP" in greeting, f"bad QMP greeting: {greeting!r}"
        self.execute("qmp_capabilities")

    def _read(self):
        while True:
            line = self.f.readline()
            if not line:
                raise RuntimeError("QMP connection closed")
            msg = json.loads(line)
            # Skip asynchronous events; return command results/greeting.
            if "event" in msg:
                continue
            return msg

    def execute(self, command, arguments=None):
        req = {"execute": command}
        if arguments:
            req["arguments"] = arguments
        self.f.write(json.dumps(req).encode() + b"\n")
        resp = self._read()
        if "error" in resp:
            raise RuntimeError(f"QMP {command} failed: {resp['error']}")
        return resp.get("return")

    def screendump(self, filename):
        self.execute("screendump", {"filename": str(filename)})

    def close(self):
        try:
            self.f.close()
            self.sock.close()
        except OSError:
            pass


def assert_spike_pattern(path, fb_spike_rs):
    """Asserts the screendump is exactly the pattern fb_spike.rs paints.

    Reads the PPM with the shared strict reader (which validates the header and the
    exact payload length, so a truncated capture is a failure and not a short compare),
    then requires every pixel to match. The flat-colour smoke check runs FIRST, purely
    so a wholesale regression reports "nothing reached the panel" rather than "786,432
    pixels differ".
    """
    ppm = panel_check.read_ppm(path)
    panel_check.assert_not_flat(ppm, "spike screendump")
    expected = panel_check.expected_spike_frame(fb_spike_rs)
    panel_check.assert_frame_matches(ppm, expected, "spike screendump")
    return ppm[0], ppm[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--shim", required=True)
    ap.add_argument("--zbi", required=True)
    ap.add_argument("--qemu-data-dir", required=True)
    # The guest component's own source. The expected frame is rebuilt from its
    # constants and its paint, so the gate cannot drift into asserting a picture the
    # spike no longer draws.
    ap.add_argument("--fb-spike-rs", required=True)
    ns = ap.parse_args()
    qemu = _need(ns.qemu, "qemu")
    shim = _need(ns.shim, "shim")
    zbi = _need(ns.zbi, "zbi")
    datadir = _need(ns.qemu_data_dir, "qemu data dir")
    fb_spike_rs = _need(ns.fb_spike_rs, "fb_spike.rs")
    # Build the expectation BEFORE booting: a source change that this mirror no longer
    # describes should fail in a second, not after a ten-minute boot.
    exp_w, exp_h, _ = panel_check.expected_spike_frame(fb_spike_rs)
    print(f"[spike] expecting the exact {exp_w}x{exp_h} pattern {fb_spike_rs} paints",
          flush=True)

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    outdir = pathlib.Path(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR", str(tmp)))
    outdir.mkdir(parents=True, exist_ok=True)
    serial = tmp / "console-spike-serial.log"
    if serial.exists():
        serial.unlink()
    qmp_port = _free_port()
    screenshot = outdir / "console-spike-screendump.ppm"

    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot", "-m", "4096M",
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-qmp", f"tcp:127.0.0.1:{qmp_port},server,nowait",
           "-device", "VGA",
           "-kernel", shim, "-initrd", zbi]
    print(f"[spike] booting qemu-x64-console-spike with -device VGA + QMP", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        deadline = time.time() + BOOT_TIMEOUT_S
        while time.time() < deadline:
            txt = serial.read_text(errors="replace") if serial.exists() else ""
            # NEGATIVE ASSERTIONS FIRST, then the success needle — the order the shared
            # harness uses (tests/zircon/zbi_boot_test.py:228-243) and this one did not.
            panel_check.assert_no_panic(txt, "the boot")
            if FAIL in txt:
                tail = txt[txt.rfind(FAIL):][:400]
                raise AssertionError(f"guest framebuffer failure: {tail}")
            if RENDERED in txt:
                break
            if proc.poll() is not None:
                raise AssertionError(f"QEMU exited early ({proc.returncode})")
            time.sleep(3)
        else:
            raise AssertionError(f"timed out waiting for {RENDERED}")
        print(f"[spike] {RENDERED}; capturing QMP screendump", flush=True)

        time.sleep(1.0)  # let the last framebuffer writes settle into scanout
        qmp = Qmp("127.0.0.1", qmp_port)
        try:
            qmp.screendump(screenshot)
        finally:
            qmp.close()
        if not screenshot.is_file():
            raise AssertionError("QMP screendump produced no file")

        w, h = assert_spike_pattern(screenshot, fb_spike_rs)
        # SETTLE AND RE-READ: the pattern is judged on bytes the guest had already
        # flushed, and the process is terminated in the `finally` immediately below, so
        # without this a panic a second after the paint is never looked at. Same idea as
        # the shared harness's --settle-seconds (tests/zircon/zbi_boot_test.py:260-266).
        time.sleep(5)
        panel_check.assert_no_panic(
            serial.read_text(errors="replace"), "the boot, after the pattern was verified")
        # And the machine must still be running: `-no-reboot` means a triple fault exits
        # QEMU rather than resetting it, and the captured pixels survive that happily.
        if proc.poll() is not None:
            raise AssertionError(
                f"QEMU exited ({proc.returncode}) after the pattern was verified; the "
                "pixels were real but the machine did not survive the boot")
        print(f"[spike] PASS: {w}x{h} framebuffer captured to {screenshot} "
              f"({screenshot.stat().st_size} bytes) and every pixel of it matches the "
              f"pattern the guest's own source paints", flush=True)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
