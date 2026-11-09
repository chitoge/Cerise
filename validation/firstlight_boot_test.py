#!/usr/bin/env python3
"""Real-hardware first-light QEMU gate: the FULL UEFI GOP framebuffer path.

Boots //products:hw-x64-firstlight the exact way a real machine does — OVMF
(pflash CODE+VARS) -> efi-boot-shim from the GPT disk image's ESP
(\\EFI\\BOOT\\BOOTX64.EFI) -> bootx64.zbi -> Zircon — with a `-device VGA`
so OVMF publishes a REAL Graphics Output Protocol on it. Asserts, in order:

  1. CERISE-SHIM-GOP-FB        — the boot-shim queried GOP and emitted the
                                 ZBI_TYPE_FRAMEBUFFER item (serial print).
  1b. CERISE-PHYS-FB-CONSOLE   — physboot parsed that item and brought up its
                                 own framebuffer text console. Proven in PIXELS,
                                 not just on serial: see assert_phys_console_drew.
  1c. CERISE-KERNEL-FB-CONSOLE — the KERNEL PROPER, after the hand-off, brought
                                 up its own console on the same framebuffer.
                                 Also proven in pixels, and distinguished from
                                 physboot's drawing rather than merely following
                                 it: see assert_kernel_console_drew.
  2. CERISE-GOP-DISPLAY-OK     — gop_display bound (PCI class-0x03 composite),
                                 consumed the item via fuchsia.boot.Items,
                                 mapped the range, and serves cerise.display.
  3. CERISE-CONSOLE-RENDERED   — status_console painted the status screen on
                                 the GOP framebuffer (unchanged client code).

Then drives QMP `screendump` and asserts what is ON the panel.

WHAT THE FINAL PIXEL ASSERTION PROVES. It used to be "the screendump is not one
flat colour" — which the console's own blue title bar satisfies on its own, so
the gate this file is named for could pass with an empty panel under a header.
It now does what console_boot_test.py does, on the UEFI/GOP path:

  * the console reports its memory and CPU readings as RAW values on serial,
    and only after the paint that contained them (a -UNAVAILABLE metric emits
    that INSTEAD, never as well);
  * this harness validates those raw values against things it configured and the
    guest does not get to choose — the `-m` and `-smp` it passed QEMU;
  * it formats the expected on-screen text ITSELF from those validated numbers,
    rather than searching for a string the console handed it; and
  * it finds that text on the framebuffer by exact full-cell glyph comparison,
    foreground AND background, anchored to its own label, using the font parsed
    out of the renderer's own font.rs, requiring exactly one match.

Storage is deliberately NOT required here: this product's console realm never
starts fshost, and there is no data disk on the gate's QEMU command line, so the
disk metric is honestly unavailable and requiring it would be requiring a
failure. That also means this gate proves NOTHING about the Storage section —
a regression confined to it passes here, and only :console-boot covers it.

EXACTLY WHAT THE PASS MEANS, stated narrowly on purpose. It means: these two
measured values were painted in a frame captured during this boot, they matched
what the harness gave QEMU, and they were still the console's current readings
immediately after the capture. It does NOT mean the panel is repainting: the
console re-emits its evidence only when a value's stable identity changes
(status_console/src/main.rs, `evidence_key`), so a framebuffer frozen on a frame
whose memory total and core count have not changed would satisfy this. Proving
liveness needs a paint-generation token the console does not yet draw; until it
does, do not read this gate as proof that the panel is still updating.

This disk image (firstlight-uefi-disk) is byte-identical to the dd-able USB
image; this gate is its QEMU rehearsal.
"""
from __future__ import annotations
import argparse, gzip, json, os, pathlib, random, shutil, socket, subprocess, sys, time

import panel_check

SHIM_GOP = "CERISE-SHIM-GOP-FB"
PHYS_FB = "CERISE-PHYS-FB-CONSOLE"
KERNEL_FB = "CERISE-KERNEL-FB-CONSOLE"
DISPLAY_OK = "CERISE-GOP-DISPLAY-OK"
CONSOLE_RENDERED = "CERISE-CONSOLE-RENDERED"
CONSOLE_FAIL = "CERISE-CONSOLE-FAIL"
FAIL_MARKERS = [CONSOLE_FAIL, "ZBI_TYPE_FRAMEBUFFER omitted"]
BOOT_TIMEOUT_S = 600.0

# The console's raw-value evidence. Emitted only after a paint that contained the value.
MEM_OK = "CERISE-CONSOLE-MEM-OK"
CPU_OK = "CERISE-CONSOLE-CPU-OK"

# What this harness gives QEMU, and therefore the oracle the guest's own numbers are
# checked against. Keep these and the -m/-smp flags below in step.
#
# THE CPU COUNT IS DRAWN PER RUN, and that is the point. With a constant, the cheapest
# implementation that satisfies "the panel shows the right core count" is a panel that
# draws that constant — and no run of the gate could tell the two apart, because the
# oracle never moves. A value chosen at launch cannot be hardcoded in the guest: a panel
# that always says 2 is red on two runs in three. The randomized oracle makes
# that otherwise-cheap false implementation observable.
# The chosen value is printed, so a failure says which machine it was.
GUEST_MEM_MB = 2048
GUEST_SMP = random.choice((2, 3, 4))


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Qmp:
    """Minimal QMP client over TCP (bazel TEST_TMPDIR exceeds AF_UNIX limits)."""

    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.f = self.sock.makefile("rwb", buffering=0)
        assert "QMP" in self._read(), "bad QMP greeting"
        self.execute("qmp_capabilities")

    def _read(self):
        while True:
            line = self.f.readline()
            if not line:
                raise RuntimeError("QMP connection closed")
            msg = json.loads(line)
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

    def close(self):
        try:
            self.f.close()
            self.sock.close()
        except OSError:
            pass


def check_reported_values(text):
    """Validates the console's RAW numbers against what this harness configured.

    The independent-oracle step. Every bound here comes from a value the harness chose
    (QEMU's -m and -smp), so a hardcoded or placeholder number in the guest cannot
    satisfy them. Read through `panel_check.metric_settled`, not the last -OK line, so a
    metric that went UNAVAILABLE after its last good reading fails here instead of being
    validated against a stale success — which is why this is called again after the
    capture.
    """
    for family in ("MEM", "CPU"):
        fields, why = panel_check.metric_settled(text, family)
        if fields is None:
            raise AssertionError(f"{family} is not currently available on the panel: {why}")

    mem = panel_check.last_marker(text, MEM_OK)
    total_bytes = panel_check.int_field(mem, "total_bytes", MEM_OK)
    free_bytes = panel_check.int_field(mem, "free_bytes", MEM_OK)
    used_bytes = panel_check.int_field(mem, "used_bytes", MEM_OK)
    limit = GUEST_MEM_MB * (1 << 20)
    # The kernel never sees quite all of -m (firmware and bootloader reservations take a
    # bite, and under OVMF a larger one than on the direct-kernel path) and it cannot see
    # more. A 10% floor still pins the value to within a tenth of whatever GUEST_MEM_MB
    # says, so a constant cannot satisfy it across configurations.
    floor = limit - limit // 10
    if not (floor < total_bytes <= limit):
        raise AssertionError(
            f"reported memory total {total_bytes} B is not a reading of the "
            f"{GUEST_MEM_MB} MiB given to QEMU (expected {floor} < x <= {limit})"
        )
    if not (0 < free_bytes < total_bytes):
        raise AssertionError(f"free {free_bytes} B is not between 0 and total {total_bytes} B")
    if used_bytes != total_bytes - free_bytes:
        raise AssertionError(f"used {used_bytes} != total {total_bytes} - free {free_bytes}")

    cpu = panel_check.last_marker(text, CPU_OK)
    cores = panel_check.int_field(cpu, "cores", CPU_OK)
    if cores != GUEST_SMP:
        raise AssertionError(f"reported {cores} cores, QEMU was configured with {GUEST_SMP}")
    reported = panel_check.int_field(cpu, "reported", CPU_OK)
    if reported != cores:
        raise AssertionError(
            f"the kernel says {cores} CPUs exist but only {reported} were sampled; the "
            "per-core figures on the panel would not describe the whole machine"
        )
    interval_ns = panel_check.int_field(cpu, "interval_ns", CPU_OK)
    idle_delta_ns = panel_check.int_field(cpu, "idle_delta_ns", CPU_OK)
    # Utilisation is a delta, so these prove the sample came from two separated
    # observations of a kernel counter that really advanced. A constant produces neither.
    if interval_ns <= 0:
        raise AssertionError(f"CPU sample interval {interval_ns} ns: no time elapsed")
    if idle_delta_ns <= 0:
        raise AssertionError(
            f"idle time advanced by {idle_delta_ns} ns across {interval_ns} ns: an idle "
            "guest must accumulate idle time, so this is not a live reading")
    if idle_delta_ns > interval_ns * reported:
        raise AssertionError(
            f"{reported} core(s) reported {idle_delta_ns} ns idle across {interval_ns} ns "
            "of wall time, which is more idle time than existed")
    return {"mem_total": total_bytes, "cores": cores}


def assert_panel_shows(screenshot, font, values):
    """Asserts the validated numbers are physically drawn on the GOP framebuffer.

    The expected strings are formatted HERE, from the raw numbers already validated
    above — never scraped from the guest's own output.
    """
    ppm = panel_check.read_ppm(screenshot)
    # Cheap first, so a wholesale regression says "nothing reached the panel" rather
    # than "the glyph was not found". This is the ONLY thing the old assertion did.
    panel_check.assert_not_flat(ppm, "GOP screendump")
    found = {
        "memory": panel_check.assert_panel_value(
            ppm, font, "total", panel_check.mib(values["mem_total"]), "Memory total"
        ),
        "cpu": panel_check.assert_panel_value(
            ppm, font, "cores", str(values["cores"]), "CPU core count"
        ),
    }
    # STRUCTURAL, not coordinate-hardcoded. Both rows are drawn by Column::row in the one
    # right-hand column, so they share an x, and the sections render in a fixed order, so
    # Memory is above CPU. That rules out the two strings being found scattered anywhere
    # on the screen — which a whole-framebuffer search alone would allow — without
    # freezing the layout into the test.
    if found["memory"][0] != found["cpu"][0]:
        raise AssertionError(
            f"the memory and CPU rows are not in one column: {found}. They are drawn by "
            "the same Column, so a disagreement means they were found somewhere "
            "unintended."
        )
    if not found["memory"][1] < found["cpu"][1]:
        raise AssertionError(
            f"panel rows are out of section order (Memory above CPU) at {found}"
        )
    return ppm, found


def _read_ppm(path):
    """Returns (width, height, pixels) for a P6 PPM."""
    data = pathlib.Path(path).read_bytes()
    assert data.startswith(b"P6"), f"screendump is not a P6 PPM: {data[:16]!r}"
    idx, tokens = 2, []
    while len(tokens) < 3:
        while idx < len(data) and data[idx] in b" \t\r\n":
            idx += 1
        start = idx
        while idx < len(data) and data[idx] not in b" \t\r\n":
            idx += 1
        tokens.append(data[start:idx])
    width, height, _ = (int(t) for t in tokens)
    idx += 1
    return width, height, data[idx:]


# The phys console's first text row. Its glyph cell is 8px scaled by 2 on any
# panel >= 1280 wide, so its first line lives in scanlines 0..15; 16 is the
# tightest band that is certain to contain it and nothing below it.
PHYS_FB_FIRST_ROW_SCANLINES = 16


def _lit_pixels_in_top_band(path, scanlines=PHYS_FB_FIRST_ROW_SCANLINES):
    """Counts non-black pixels in the top `scanlines` rows of a screendump."""
    width, height, pixels = _read_ppm(path)
    band = min(scanlines, height)
    lit = 0
    for y in range(band):
        row = (y * width) * 3
        for x in range(width):
            off = row + x * 3
            if pixels[off] or pixels[off + 1] or pixels[off + 2]:
                lit += 1
    return width, height, lit


# The kernel console's banner occupies the top text row: 8 scanlines, or 16 on
# a panel wide enough for the 2x magnification. Scanning 16 covers both.
BANNER_SCANLINES = 16


def _has_fully_lit_scanline(path, scanlines=BANNER_SCANLINES):
    """True if any of the top `scanlines` rows has no black pixel at all."""
    width, height, pixels = _read_ppm(path)
    for y in range(min(scanlines, height)):
        row = y * width * 3
        if all(pixels[row + x * 3] or pixels[row + x * 3 + 1] or pixels[row + x * 3 + 2]
               for x in range(width)):
            return True
    return False


def _screendump(qmp_port, path):
    qmp = Qmp("127.0.0.1", qmp_port)
    try:
        qmp.execute("screendump", {"filename": str(path)})
    finally:
        qmp.close()
    if not pathlib.Path(path).is_file():
        raise AssertionError(f"QMP screendump produced no file: {path}")
    return path


def assert_phys_console_drew(shim_shot, phys_shot):
    """Proves physboot's framebuffer console really put glyphs on the panel.

    physboot's console clears the whole framebuffer and starts writing at the
    very top-left, so its first line lands in scanline 0. The boot shim's own
    output does NOT reach there: OVMF centres its text grid, leaving the top of
    the screen black. So "lit pixels in the top scanlines" separates the two
    cleanly, without needing to OCR the text or duplicate the font here.

    Both halves are asserted so the check cannot pass vacuously: the capture
    taken while only the shim had drawn MUST have an empty top band, and the
    capture taken once physboot announced its console MUST have a non-empty one.
    If the shim ever started painting the top row, the first assert fails loudly
    rather than the second one silently becoming meaningless.

    What this does NOT prove, now that the kernel has a console of its own, is
    WHICH of the two drew: physboot hands off within milliseconds of announcing
    itself, so the second capture usually already shows the kernel's screen. It
    proves a framebuffer console rendered before userspace existed, which is the
    claim it was written for. assert_kernel_console_drew below is what separates
    the two stages.
    """
    w0, h0, shim_lit = _lit_pixels_in_top_band(shim_shot)
    assert shim_lit == 0, (
        f"pre-kernel capture already has {shim_lit} lit pixels in the top "
        f"{PHYS_FB_FIRST_ROW_SCANLINES} scanlines, so that band no longer "
        f"distinguishes physboot's console from the boot shim's output")
    w1, h1, phys_lit = _lit_pixels_in_top_band(phys_shot)
    assert (w1, h1) == (w0, h0), f"screendump geometry changed {w0}x{h0} -> {w1}x{h1}"
    assert phys_lit > 0, (
        f"{PHYS_FB} was printed on serial but the top {PHYS_FB_FIRST_ROW_SCANLINES} "
        f"scanlines of the framebuffer are still black: physboot parsed the "
        f"ZBI_TYPE_FRAMEBUFFER item but drew nothing")
    return phys_lit


def assert_kernel_console_drew(shim_shot, kernel_shot, shim_shot_raced=False):
    """Proves the KERNEL, not just physboot, put its console on the panel.

    "The top of the screen has text on it" cannot tell the two apart: both
    consoles clear the framebuffer and both start at the top-left, so physboot's
    drawing satisfies it on its own. Worse, the two are only milliseconds apart,
    so the capture taken when physboot announced its console usually already
    shows the kernel's. Any check phrased as "more lit than physboot" would be
    comparing a capture against itself -- the same kind of measurement artifact
    that made "the panel is frozen at the shim's last line" mean nothing.

    So the discriminator is a signature no amount of text can forge: a scanline
    with not one black pixel in it. The kernel's banner underlines itself with a
    refilled scanline for exactly this purpose, while every glyph in the font has
    gaps, so text can never light a whole scanline however long the line is. The
    control is the capture taken before the kernel existed at all, which must not
    have one; feeding it in as the kernel capture is how this check was verified
    to fail when it should.
    """
    # The control is only a control if the pre-kernel capture really was taken
    # pre-kernel. That capture races (see where it is taken), so when the caller
    # has established it landed late, skip the control rather than assert a
    # property of a capture we know is void -- otherwise this fails describing a
    # scanline, which says nothing about the race that actually caused it.
    if not shim_shot_raced:
        assert not _has_fully_lit_scanline(shim_shot), (
            f"the pre-kernel capture already has a fully lit scanline in its top "
            f"{BANNER_SCANLINES}, so that signature no longer identifies the kernel's "
            f"banner")
    assert _has_fully_lit_scanline(kernel_shot), (
        f"{KERNEL_FB} was printed on serial but no scanline in the top "
        f"{BANNER_SCANLINES} of the framebuffer is fully lit: the kernel reported "
        f"a framebuffer console but its banner is not on the panel")


def _wait_for(serial, needle, fail_needles, proc, deadline):
    while time.time() < deadline:
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        # NEGATIVE ASSERTIONS FIRST, then the success needle — the order the shared
        # harness uses (tests/zircon/zbi_boot_test.py:228-243) and this one did not: a
        # boot that reached the marker AND panicked is a failed boot, and testing the
        # needle first would return the panicking log as a success.
        panel_check.assert_no_panic(txt, "the boot")
        for fn in fail_needles:
            if fn in txt:
                tail = txt[txt.rfind(fn):][:400]
                raise AssertionError(f"guest failure marker: {tail}")
        if needle in txt:
            return txt
        if proc.poll() is not None:
            raise AssertionError(f"QEMU exited early ({proc.returncode})")
        time.sleep(3)
    raise AssertionError(f"timed out waiting for {needle}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--qemu-data-dir", required=True)
    ap.add_argument("--ovmf-code", required=True)
    ap.add_argument("--ovmf-vars", required=True)
    ap.add_argument("--disk", required=True)
    # The renderer's own glyph table. Parsed rather than transcribed so the gate's idea
    # of what a digit looks like cannot drift from what the console actually draws.
    ap.add_argument("--font", required=True)
    # Optional BASE:IRQ describing how to WIRE QEMU's console UART. When given,
    # the UART is placed at that PIO address and COM1 is REMOVED (-serial none).
    # That combination is what makes the cf-sz5 variant of this gate meaningful:
    # the board's `kernel.serial=ioport,<base>,<irq>` must be parsed and honoured
    # for any output to appear at all, and a silent fallback to the 0x3f8 legacy
    # UART has nowhere to land.
    #
    # The IRQ here is QEMU's wiring, NOT necessarily the board's declared IRQ.
    # QEMU's ISA bus asserts irqnum < ISA_NUM_IRQS (16), so a PCI GSI like the
    # CF-SZ5's 19 cannot be expressed at all. Using an ISA-legal stand-in is
    # sound because uart::ns8250 transmits by POLLING the line-status register's
    # tx_register_empty bit (see ns8250.h TxReady/Write) — console output never
    # depends on interrupt delivery. So this gate proves the base address and
    # the cmdline grammar, which is where the risk is, and deliberately does not
    # prove IRQ routing.
    ap.add_argument("--pio-serial", default=None, metavar="BASE:IRQ")
    ap.add_argument("--label", default="hw-x64-firstlight")
    ns = ap.parse_args()
    qemu = _need(ns.qemu, "qemu")
    datadir = _need(ns.qemu_data_dir, "qemu data dir")
    code = _need(ns.ovmf_code, "OVMF_CODE")
    vars_src = _need(ns.ovmf_vars, "OVMF_VARS")
    disk_src = _need(ns.disk, "firstlight disk image")
    # Load the font BEFORE booting: a renderer whose glyph table this parser no longer
    # understands should fail in a second, not after a ten-minute boot.
    font = panel_check.load_font(_need(ns.font, "font.rs"))

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    outdir = pathlib.Path(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR", str(tmp)))
    outdir.mkdir(parents=True, exist_ok=True)
    serial = tmp / "firstlight-serial.log"
    if serial.exists():
        serial.unlink()
    # OVMF vars and the boot disk must be writable copies (bazel inputs are RO).
    ovmf_vars = tmp / "OVMF_VARS.fd"
    shutil.copyfile(vars_src, ovmf_vars)
    os.chmod(ovmf_vars, 0o644)
    # uefi_disk_image emits a gzip-compressed image (the same artifact the flash
    # workflow zcat|dd's to USB); decompress to a writable boot copy.
    disk = tmp / "firstlight-disk.img"
    with open(disk_src, "rb") as f:
        magic = f.read(2)
    if magic == b"\x1f\x8b":
        with gzip.open(disk_src, "rb") as src, open(disk, "wb") as dst:
            shutil.copyfileobj(src, dst)
    else:
        shutil.copyfile(disk_src, disk)
    os.chmod(disk, 0o644)
    qmp_port = _free_port()
    screenshot = outdir / "firstlight-screendump.ppm"
    # Captures bracketing physboot: before it ran (shim output only) and once
    # it announced its framebuffer console. Kept as test outputs so a failure
    # can be looked at rather than guessed about.
    shim_shot = outdir / "firstlight-shim-screendump.ppm"
    phys_shot = outdir / "firstlight-physboot-screendump.ppm"
    kernel_shot = outdir / "firstlight-kernel-screendump.ppm"

    # The pre-kernel boot shim runs under UEFI and prints on the FIRMWARE console
    # (COM1 under OVMF); the kernel's UART does not exist until physboot reads
    # the ZBI cmdline. So in PIO mode the two phases land on two different ports,
    # and we watch both: SHIM_GOP on COM1, every kernel-side marker on the board's
    # PIO port. Asserting them on separate logs is what makes this rigorous — a
    # cmdline that was ignored (silent fall back to the 0x3f8 legacy UART) would
    # put the kernel markers in the COM1 log, leaving the PIO log empty and
    # failing, rather than passing on the shim's output alone.
    shim_serial = serial
    if ns.pio_serial:
        base_s, _, irq_s = ns.pio_serial.partition(":")
        base, irq = int(base_s, 0), int(irq_s, 0)
        shim_serial = tmp / "firstlight-shim-serial.log"
        if shim_serial.exists():
            shim_serial.unlink()
        serial_args = ["-serial", f"file:{shim_serial}",
                       "-chardev", f"file,id=pioserial,path={serial}",
                       "-device",
                       f"isa-serial,chardev=pioserial,iobase={base:#x},irq={irq}"]
        print(f"[firstlight] shim console on COM1; kernel console at PIO "
              f"{base:#x} IRQ {irq}", flush=True)
    else:
        serial_args = ["-serial", f"file:{serial}"]

    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot",
           # The oracle for the panel's memory and CPU rows. -smp is explicit and > 1 so
           # a console that reported a hardcoded or defaulted 1 could not satisfy it.
           "-m", f"{GUEST_MEM_MB}M", "-smp", str(GUEST_SMP),
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           *serial_args,
           "-qmp", f"tcp:127.0.0.1:{qmp_port},server,nowait",
           "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
           "-drive", f"if=pflash,format=raw,file={ovmf_vars}",
           "-drive", f"format=raw,file={disk}",
           # The GOP source: OVMF publishes a Graphics Output Protocol on this
           # VGA device; gop_display later composite-binds it (PCI class 0x03).
           "-device", "VGA"]
    print(f"[firstlight] booting {ns.label} via OVMF + GOP (full UEFI path), "
          f"-m {GUEST_MEM_MB}M -smp {GUEST_SMP} (the core count is drawn per run; the "
          f"panel must report THIS one)", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        deadline = time.time() + BOOT_TIMEOUT_S
        _wait_for(shim_serial, SHIM_GOP, FAIL_MARKERS, proc, deadline)
        print(f"[firstlight] {SHIM_GOP} (shim emitted ZBI_TYPE_FRAMEBUFFER)", flush=True)

        # Capture the panel while only the boot shim has drawn on it. This is
        # the control for the framebuffer-console check below: it is what the
        # screen looks like when physboot has NOT rendered.
        #
        # This capture races, and cannot be made not to: physboot announces its
        # console within milliseconds of SHIM_GOP, so under load the screendump
        # can land after physboot has already drawn. When that happens the
        # control is no longer a control, and the pixel assertion downstream
        # fails describing a pixel count rather than the race that caused it --
        # which is how this test earned a reputation as a flake.
        #
        # So detect the race at its source. If physboot's marker is already on
        # serial by the time the capture returns, the control is void: say so,
        # and skip the assertion that depends on it. The strictly stronger
        # kernel-console check below does not rely on this control -- it looks
        # for a fully lit scanline, which text cannot forge -- so the run still
        # proves a framebuffer console rendered.
        _screendump(qmp_port, shim_shot)
        shim_shot_raced = PHYS_FB in shim_serial.read_text(errors="replace") or (
            PHYS_FB in serial.read_text(errors="replace") if serial.exists() else False)
        if shim_shot_raced:
            print(f"[firstlight] NOTE: {PHYS_FB} already on serial when the "
                  f"pre-kernel screendump completed, so that capture is not a "
                  f"clean control; skipping the physboot pixel comparison and "
                  f"relying on the kernel-console scanline check", flush=True)

        # physboot's own framebuffer console. On the PIO variant this marker is
        # the FIRST kernel-side output, so it also proves the board's UART
        # cmdline was honoured -- the same thing the "physload" wait below
        # checks, one step earlier.
        _wait_for(serial, PHYS_FB, FAIL_MARKERS, proc, deadline)
        _screendump(qmp_port, phys_shot)
        if shim_shot_raced:
            print(f"[firstlight] {PHYS_FB} (pixel comparison skipped: no clean "
                  f"pre-kernel control this run)", flush=True)
        else:
            lit = assert_phys_console_drew(shim_shot, phys_shot)
            print(f"[firstlight] {PHYS_FB} (physboot drew {lit} pixels of text on the "
                  f"framebuffer before userspace existed)", flush=True)

        # The kernel proper's own console, on the same framebuffer, brought up
        # in the first line of lk_main -- before the debuglog, before threads,
        # before the VM. This is the marker that says the hand-off completed and
        # kernel code is running, on a machine where the serial port is the
        # thing that cannot be trusted.
        _wait_for(serial, KERNEL_FB, FAIL_MARKERS, proc, deadline)
        _screendump(qmp_port, kernel_shot)
        assert_kernel_console_drew(shim_shot, kernel_shot, shim_shot_raced)
        print(f"[firstlight] {KERNEL_FB} (the kernel's banner is on the panel: a "
              f"scanline with no black pixel in it, which text cannot draw)", flush=True)

        if ns.pio_serial:
            # Everything from here must arrive on the board's PIO port, which
            # only exists because the kernel parsed `kernel.serial=ioport,...`.
            _wait_for(serial, "physload", FAIL_MARKERS, proc, deadline)
            print("[firstlight] kernel console alive on the board's PIO port",
                  flush=True)
        _wait_for(serial, DISPLAY_OK, FAIL_MARKERS, proc, deadline)
        print(f"[firstlight] {DISPLAY_OK} (gop_display bound + serving)", flush=True)
        _wait_for(serial, CONSOLE_RENDERED, FAIL_MARKERS, proc, deadline)
        print(f"[firstlight] {CONSOLE_RENDERED} (status screen painted)", flush=True)

        # The metrics markers are emitted only AFTER a paint that contained them, and a
        # metric that could not be read emits its -UNAVAILABLE instead. Wait for memory
        # and CPU to SETTLE into -OK: CPU utilisation needs a second sample, so the
        # earliest frames are honestly incomplete and screenshotting one would prove
        # nothing. A metric that never settles times out; one that settles unavailable
        # never satisfies this loop. (Storage is not required — see the module docstring.)
        pending = ""
        while time.time() < deadline:
            text = serial.read_text(errors="replace") if serial.exists() else ""
            panel_check.assert_no_panic(text, "the boot")
            for fn in FAIL_MARKERS:
                if fn in text:
                    raise AssertionError(f"guest failure marker: {text[text.rfind(fn):][:400]}")
            states = {f: panel_check.metric_settled(text, f) for f in ("MEM", "CPU")}
            unsettled = [f"{f}: {why or 'no marker yet'}"
                         for f, (ok, why) in states.items() if ok is None]
            if not unsettled:
                break
            pending = "; ".join(unsettled)
            if proc.poll() is not None:
                raise AssertionError(f"QEMU exited early ({proc.returncode})")
            time.sleep(3)
        else:
            raise AssertionError(f"metrics never settled on the panel: {pending}")

        values = check_reported_values(text)
        print(f"[firstlight] raw values validated against this harness's own QEMU "
              f"configuration: {values}", flush=True)

        # `render` clears the whole framebuffer before redrawing, so a single dump can
        # land mid-repaint and catch a blank or half-drawn frame. Retry until a COMPLETE
        # frame carrying both values is captured, or the deadline expires. The values are
        # stable, so any complete frame will do.
        # Bounded, and deliberately much shorter than the boot deadline: the panel
        # repaints every couple of seconds, so a minute of identical failures is a panel
        # that is not going to draw the value, not a capture that keeps landing badly.
        # Running this loop to the full boot deadline turned a real red into a ten-minute
        # one (measured), which is how a gate stops being run.
        last_err = None
        capture_deadline = min(deadline, time.time() + 120.0)
        while time.time() < capture_deadline:
            _screendump(qmp_port, screenshot)
            try:
                ppm, found = assert_panel_shows(screenshot, font, values)
                # RE-READ THE SERIAL LOG AFTER the capture and require the identity to be
                # unchanged and still settled. Without this the gate could validate an
                # early frame and never notice a metric that went unavailable afterwards,
                # or accept a stale screenshot whose values had since moved.
                after = serial.read_text(errors="replace")
                if check_reported_values(after) != values:
                    raise AssertionError(
                        "the reported values changed between validation and capture; "
                        "the screendump does not describe the current panel")
                break
            except AssertionError as e:
                last_err = e
                if proc.poll() is not None:
                    raise AssertionError(f"QEMU exited early ({proc.returncode})") from e
                time.sleep(2)
        else:
            raise AssertionError(f"panel never showed the reported values: {last_err}")

        # SETTLE AND RE-READ. Everything above is decided on bytes the guest had already
        # flushed; a panic a moment later would never be looked at, because the process is
        # terminated in the `finally` immediately after this. The shared harness solved
        # this with --settle-seconds (tests/zircon/zbi_boot_test.py:260-266); this is the
        # same idea in the two harnesses that do not use it.
        time.sleep(5)
        panel_check.assert_no_panic(
            serial.read_text(errors="replace"), "the boot, after the panel was verified")
        # And the machine must still be running. `-no-reboot` means a triple fault exits
        # QEMU rather than resetting it, and the captured pixels would survive that
        # perfectly happily. Nothing else on the success path looks at the process.
        if proc.poll() is not None:
            raise AssertionError(
                f"QEMU exited ({proc.returncode}) after the panel was verified; the "
                "pixels were real but the machine did not survive the boot")

        w, h, _ = ppm
        print(f"[firstlight] PASS: {w}x{h} GOP status screen captured to {screenshot} "
              f"({screenshot.stat().st_size} bytes). Verified ON SCREEN by exact "
              f"full-cell glyph match: memory total "
              f"{panel_check.mib(values['mem_total'])} at {found['memory']}, CPU cores "
              f"{values['cores']} at {found['cpu']}", flush=True)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
