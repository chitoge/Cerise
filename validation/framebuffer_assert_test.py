#!/usr/bin/env python3
"""Negative control for the framebuffer gates' pixel assertions.

WHY THIS EXISTS. Three live gates used to assert only that a screendump was "not one
flat colour". Nothing in the tree ever demonstrated what that did and did not reject, so
the assertion sat there for months looking like a pixel proof while a title bar
satisfied it. The replacements — an exact frame match for the fb_spike gate and an
anchored full-cell glyph match for the console/first-light panels — are stronger, but
"stronger" is a claim, and an untested claim about a checker is exactly the thing this
suite keeps getting wrong.

So this target BUILDS THE FRAMES A WRONG IMPLEMENTATION WOULD PRODUCE and requires the
assertions to reject every one of them. It runs on the host in under a second, needs no
QEMU, and it is the only place in the tree where these checkers are proven able to go
red at all. It is deliberately in //validation:all rather than manual: the live gates it
speaks for are manual, so if this were manual too, nothing would ever run it.

Read the two halves as answers to "what is the cheapest implementation that would
satisfy this assertion without doing the work?":

  * fb_spike — bring the mode up and paint one stripe; paint the pattern at the wrong
    offset; paint the rectangles in the wrong colours; paint the outlines only. Each is
    a frame the old check called PASS, and each is asserted red here.

  * the status panel — draw the chrome and no values; draw a plausible number that is
    not the measured one; draw the right text in the wrong colour (so the panel says
    "down" in the "up" colour); draw the value without its label, or twice.

The positive cases are deliberately weak evidence and are here only to prove the checker
is not rejecting everything: this file renders the good frames with its own copy of the
drawing rule, so a bug shared by both sides would not show up. The live gates are what
prove the real renderer draws them — //validation:console-spike-boot has been run
against a deliberately broken fb_raw.rs and failed, and against the real one and passed.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

import panel_check

FAILURES: list[str] = []
CHECKS = 0


def expect_red(what: str, fn) -> None:
    """Requires `fn` to raise AssertionError. A checker that cannot go red is not a
    checker, and this is the only place that ever asks these ones to."""
    global CHECKS
    CHECKS += 1
    try:
        fn()
    except AssertionError as e:
        first = str(e).split("\n")[0]
        print(f"  RED (correct): {what}\n         -> {first[:160]}")
        return
    FAILURES.append(f"{what}: the assertion ACCEPTED a frame it must reject")
    print(f"  GREEN (WRONG): {what}")


def expect_green(what: str, fn) -> None:
    global CHECKS
    CHECKS += 1
    try:
        fn()
    except AssertionError as e:
        FAILURES.append(f"{what}: rejected a frame it must accept: {e}")
        print(f"  RED (WRONG): {what}\n         -> {str(e).splitlines()[0][:200]}")
        return
    print(f"  GREEN (correct): {what}")


# ---------------------------------------------------------------------------
# Frame construction
# ---------------------------------------------------------------------------


def rgb(value: int) -> bytes:
    return bytes(((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF))


class Frame:
    """A mutable RGB frame that can be handed to the checkers as a (w, h, bytes) PPM."""

    def __init__(self, width: int, height: int, bg: int):
        self.width, self.height = width, height
        self.pix = bytearray(rgb(bg) * (width * height))

    def fill(self, x: int, y: int, w: int, h: int, colour: int) -> None:
        row = rgb(colour) * w
        for yy in range(y, y + h):
            off = (yy * self.width + x) * 3
            self.pix[off : off + w * 3] = row

    def draw_text(self, font, x: int, y: int, spans, bg: int, scale: int = 2) -> None:
        """The renderer's rule: each 8x8 glyph bit becomes a scale x scale block, set
        bits in the span's colour and clear bits in the background."""
        cell = 0
        for text, colour in spans:
            for ch in text:
                rows = font[ch]
                for ry, bits in enumerate(rows):
                    for rx in range(8):
                        c = colour if (bits >> (7 - rx)) & 1 else bg
                        self.fill(x + (cell * 8 + rx) * scale, y + ry * scale, scale, scale, c)
                cell += 1

    def ppm(self) -> tuple[int, int, bytes]:
        return self.width, self.height, bytes(self.pix)


def old_check_passes(frame: Frame) -> bool:
    """The assertion these gates used to make, verbatim: 'not one flat colour'.

    Kept so this file can state, as a measurement rather than an opinion, which of the
    known-bad frames below the old gates called green.
    """
    sample = bytes(frame.pix)
    first = sample[0:3]
    return any(sample[i : i + 3] != first for i in range(0, len(sample), 3))


# ---------------------------------------------------------------------------
# Half 1: the fb_spike exact-frame assertion
# ---------------------------------------------------------------------------


def spike_checks(fb_spike_rs: str) -> None:
    print("fb_spike exact-frame assertion (//validation:console-spike-boot):")
    w, h, good = panel_check.expected_spike_frame(fb_spike_rs)
    consts = panel_check._rust_consts(pathlib.Path(fb_spike_rs), panel_check._SPIKE_CONSTS)
    bg, panel_c = consts["BG"], consts["PANEL"]

    def check(frame_bytes: tuple[int, int, bytes]):
        panel_check.assert_frame_matches(frame_bytes, (w, h, good), "frame")

    expect_green("the exact frame fb_spike.rs paints", lambda: check((w, h, good)))

    # 1. The whole point: a decorated but essentially blank frame.
    stripe = Frame(w, h, bg)
    stripe.fill(0, 0, w, 32, panel_c)
    assert old_check_passes(stripe), "the old check must accept this, or the point is lost"
    expect_red("mode set, one title-bar stripe painted (the old check passed this)",
               lambda: check(stripe.ppm()))

    # 2. Every rectangle drawn as an 8px stripe at its top edge — the shape of the real
    #    broken run this gate was proven red against (a partial-paint fill_rect).
    partial = Frame(w, h, bg)
    third, bar_y = w // 3, h * 2 // 3
    for i, colour in enumerate((consts["BAR_R"], consts["BAR_G"], consts["BAR_B"])):
        partial.fill(i * third, bar_y, third, 8, colour)
    pw, ph = w // 2, h // 3
    px, py = (w - pw) // 2, h // 6
    partial.fill(px, py, pw, 8, panel_c)
    assert old_check_passes(partial)
    expect_red("every rect painted as an 8px stripe (partial-paint implementation)",
               lambda: check(partial.ppm()))

    # 3. Right picture, wrong colours: a channel-swapped write (BGR where the device
    #    scans out RGB) is a real and easy bug, and it looks perfectly structured.
    swapped = bytearray(good)
    for i in range(0, len(swapped), 3):
        swapped[i], swapped[i + 2] = swapped[i + 2], swapped[i]
    expect_red("the whole pattern with R and B swapped (wrong pixel format)",
               lambda: check((w, h, bytes(swapped))))

    # 4. Right picture, wrong place: an off-by-one stride/origin.
    shifted = Frame(w, h, bg)
    shifted.pix[3:] = good[: len(good) - 3]
    expect_red("the whole pattern shifted one pixel (stride/origin error)",
               lambda: check(shifted.ppm()))

    # 5. The inset never drawn — a solid panel where a nested one is specified.
    solid = bytearray(good)
    solid_frame = Frame(w, h, bg)
    solid_frame.pix = solid
    solid_frame.fill(px + 16, py + 16, pw - 32, ph - 32, panel_c)
    expect_red("the amber panel drawn solid (its inset never painted)",
               lambda: check(solid_frame.ppm()))

    # 6. A truncated capture must fail AS TRUNCATION, through the real PPM reader the
    #    gate uses — not by handing the comparator a short tuple, which would exercise
    #    a path no live capture can take.
    tmpdir = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    short = tmpdir / "truncated.ppm"
    short.write_bytes(f"P6\n{w} {h}\n255\n".encode() + good[: len(good) // 2])
    expect_red("a capture short of a full frame, read back through read_ppm",
               lambda: panel_check.read_ppm(short))
    full = tmpdir / "full.ppm"
    full.write_bytes(f"P6\n{w} {h}\n255\n".encode() + good)
    expect_green("a complete capture read back through read_ppm",
                 lambda: check(panel_check.read_ppm(full)))

    # 7. The drift guard: an expectation built from a source whose paint changed must
    #    fail loudly rather than silently describing a picture nobody draws.
    src = pathlib.Path(fb_spike_rs).read_text()
    tmp = tmpdir / "_fb_spike_drift.rs"

    def from_source(text: str):
        tmp.write_text(text)
        return panel_check.expected_spike_frame(tmp)

    expect_red("fb_spike.rs's paint changed but the mirror did not",
               lambda: from_source(src.replace("fb.fill_rect(px + 16",
                                               "fb.fill_rect(px + 24", 1)))

    # 8. SOURCE CO-DEGENERATION — the failure mode that survives everything above,
    #    because both the guest and the expectation are built from the same file. If the
    #    spike shrank its mode, or collapsed two of its five colours into one, the
    #    "exact frame" would still match while the picture became something a single
    #    fill could paint. These require the gate's own floors to catch it, and they are
    #    the reason those floors are stated in panel_check rather than read from source.
    #    These assertions keep the two independently meaningful.
    expect_red("the spike collapsing two of its five colours into one",
               lambda: from_source(src.replace("const BAR_G: u32 = 0x0022_CC22;",
                                               "const BAR_G: u32 = 0x0011_2244;", 1)))
    expect_red("the spike dropping to a mode too small to discriminate",
               lambda: from_source(
                   src.replace("const WIDTH: usize = 1024;", "const WIDTH: usize = 64;", 1)
                      .replace("const HEIGHT: usize = 768;", "const HEIGHT: usize = 48;", 1)))
    tmp.unlink()


# ---------------------------------------------------------------------------
# Half 2: the status panel's anchored glyph assertion
# ---------------------------------------------------------------------------


def panel_checks(font_rs: str) -> None:
    print("status-panel glyph assertion (//validation:console-boot, "
          ":firstlight-uefi-boot):")
    font = panel_check.load_font(font_rs)
    W, H = 1024, 768
    label, value = "total", "2047 MiB"
    spans = [(label.ljust(panel_check.LABEL_CELLS), panel_check.C_LABEL),
             (value, panel_check.C_VALUE)]

    def frame_with(spans_, x=300, y=200, bg=panel_check.C_BG) -> Frame:
        f = Frame(W, H, bg)
        # The chrome a "decorated" panel has: a title bar and a rule. Present in every
        # case below, good and bad, so no result here can be explained by its absence.
        f.fill(0, 0, W, 40, panel_check.C_UP)
        f.fill(0, 44, W, 2, panel_check.C_SUBTLE)
        if spans_:
            f.draw_text(font, x, y, spans_, bg)
        return f

    def check(frame: Frame, val=value):
        panel_check.assert_panel_value(frame.ppm(), font, label, val, "Memory total")

    expect_green("the label and value drawn as the renderer draws them",
                 lambda: check(frame_with(spans)))

    # 1. Failure #6 itself: chrome, no values. This is the frame that made the old
    #    assertion worthless, and the one the brief asks to be shown failing.
    blank = frame_with(None)
    assert old_check_passes(blank), "the old check must accept a blank-but-decorated frame"
    expect_red("blank panel with a title bar and a rule (the old check passed this)",
               lambda: check(blank))

    # 2. A plausible number that is not the measured one. Off by one MiB.
    expect_red("the panel drawing 2048 MiB where the measurement said 2047",
               lambda: check(frame_with([(label.ljust(panel_check.LABEL_CELLS),
                                          panel_check.C_LABEL),
                                         ("2048 MiB", panel_check.C_VALUE)])))

    # 3. Right text, wrong colour — the class the full-cell comparison exists for. A
    #    panel that renders a down interface in the up colour is wrong on screen and
    #    identical to a correct one under any foreground-only matcher.
    expect_red("the value drawn in the label colour instead of the value colour",
               lambda: check(frame_with([(label.ljust(panel_check.LABEL_CELLS),
                                          panel_check.C_LABEL),
                                         (value, panel_check.C_LABEL)])))

    # 4. The value with no label: unanchored digits, which the panel is full of.
    expect_red("the value drawn without its label (unanchored)",
               lambda: check(frame_with([(value, panel_check.C_VALUE)])))

    # 5. A denser glyph must not satisfy a sparser one. Foreground-only matching would
    #    accept an 8 for a 3; the background half is what rules it out.
    expect_red("a denser digit standing in for the expected one (8 for 3)",
               lambda: panel_check.assert_panel_value(
                   frame_with([(label.ljust(panel_check.LABEL_CELLS), panel_check.C_LABEL),
                               ("2887 MiB", panel_check.C_VALUE)]).ppm(),
                   font, label, "2337 MiB", "Memory total"))

    # 6. Two matches is not a stronger pass, it is an untrustworthy one.
    twice = frame_with(spans)
    twice.draw_text(font, 300, 400, spans, panel_check.C_BG)
    expect_red("the same row drawn twice (uniqueness)", lambda: check(twice))

    # 7. Drawn on the wrong background: the row is there, but the panel behind it is
    #    not the panel's background, so the full-cell comparison must reject it.
    expect_red("the row drawn over the wrong background colour",
               lambda: check(frame_with(spans, bg=panel_check.C_DOWN)))


# ---------------------------------------------------------------------------
# Half 3: the evidence-marker parser, which decides what the panel is compared to
# ---------------------------------------------------------------------------


def marker_checks() -> None:
    print("console evidence-marker parser (panel_check.metric_settled):")
    ok = "CERISE-CONSOLE-MEM-OK: total_bytes=2146631680 free_bytes=100 used_bytes=99\n"
    bad = "CERISE-CONSOLE-MEM-UNAVAILABLE: no memory stats\n"

    def settled(text):
        fields, why = panel_check.metric_settled(text, "MEM")
        if fields is None:
            raise AssertionError(f"not settled: {why}")
        return fields

    def settled_exactly(text):
        """Green is not enough: the parser must return the RIGHT fields, or a gate would
        validate the guest's numbers against a misparse."""
        fields = settled(text)
        want = {"total_bytes": "2146631680", "free_bytes": "100", "used_bytes": "99"}
        if fields != want:
            raise AssertionError(f"parsed {fields}, expected {want}")
        if panel_check.last_marker(text, "CERISE-CONSOLE-MEM-OK") != want:
            raise AssertionError("last_marker disagrees with metric_settled")
        if panel_check.int_field(fields, "total_bytes", "MEM") != 2146631680:
            raise AssertionError("int_field did not return the integer it parsed")

    expect_green("an -OK after an early -UNAVAILABLE is settled, with exactly its fields",
                 lambda: settled_exactly(bad + ok))
    expect_red("a metric that went UNAVAILABLE after its last -OK",
               lambda: settled(ok + bad))
    expect_red("no marker at all", lambda: settled("booting...\n"))
    # The reason the parse is line-anchored: another component quoting the marker inside
    # an error message is not evidence that the panel drew anything.
    expect_red("the marker quoted inside another component's log line",
               lambda: settled("ERROR: expected CERISE-CONSOLE-MEM-OK: total_bytes=1 "
                               "but the console never started\n"))
    expect_red("an -OK line carrying no fields",
               lambda: settled("CERISE-CONSOLE-MEM-OK:\n"))

    print("panic detection (panel_check.assert_no_panic):")
    rendered = "CERISE-CONSOLE-RENDERED\nCERISE-FBSPIKE-RENDERED\n"
    expect_green("a clean log", lambda: panel_check.assert_no_panic(rendered, "boot"))
    # The case the three framebuffer gates could not see until now: the panel is painted,
    # the success marker is printed, and THEN the kernel dies. The pixels are still on
    # the screen, so every pixel assertion in this file still passes on that boot.
    for pattern in panel_check.PANIC_PATTERNS:
        expect_red(f"a boot that rendered and then hit {pattern!r}",
                   lambda p=pattern: panel_check.assert_no_panic(
                       rendered + f"ZIRCON KERNEL OOPS\n{p}: something died\n", "boot"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--font", required=True)
    ap.add_argument("--fb-spike-rs", required=True)
    ns = ap.parse_args()
    spike_checks(ns.fb_spike_rs)
    panel_checks(ns.font)
    marker_checks()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} of {CHECKS} controls did not behave as required:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"OK: {CHECKS} controls behaved as required — every known-bad frame was "
          f"rejected and every good one accepted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
