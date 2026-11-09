#!/usr/bin/env python3
"""Anchored, full-cell glyph matching against a QMP screendump of the status panel.

WHY THIS EXISTS. The console gate used to assert only that the framebuffer was not one
flat colour, which a blue title bar alone satisfies. That proves a display driver, not a
panel. This module lets a gate assert that a SPECIFIC value, in a SPECIFIC colour, next
to its OWN label, is physically drawn on the screen.

The three properties that make the assertion hard to pass by accident:

  * ANCHORED BY ITS LABEL. The pattern is the label and the value as one contiguous run
    of cells, each with its own expected colour. "4095 MiB" alone could be matched by
    almost anything with digits in it, and the panel is full of digits (IP addresses,
    prefix lengths, a port). "total     4095 MiB", with "total" in the label colour and
    the digits in the value colour, cannot.

  * FULL CELL, FOREGROUND AND BACKGROUND. Every set bit of the glyph must be exactly the
    expected colour AND every clear bit must be exactly the background. Checking only the
    set bits would let a denser glyph (an 8 satisfying a 3, say) pass as a superset.

  * UNIQUENESS. The caller requires exactly one match. Two matches mean the pattern was
    not as specific as it looked and the result is not trustworthy either way.

The font is PARSED FROM font.rs at runtime, not transcribed. A copy would drift from the
renderer silently, and a matcher that has quietly stopped describing the real glyphs is a
matcher that passes for the wrong reason.

Colour note: the console writes little-endian 0x00RRGGBB words to the framebuffer
(cerise.display's X8R8G8B8, so bytes B,G,R,X in memory), and QEMU's P6 PPM is packed RGB.
A colour constant 0xRRGGBB therefore compares against PPM bytes RR,GG,BB in that order —
NOT the framebuffer's byte order.

This module also carries two things every framebuffer gate needs and used to keep its own
private copy of:

  * `metric_settled` / `last_marker` / `int_field` — the anchored parse of the console's
    CERISE-CONSOLE-{MEM,CPU,DISK}-{OK,UNAVAILABLE} evidence markers. One copy, because two
    copies of a parser are two parsers that drift.

  * `expected_spike_frame` / `assert_frame_matches` — the STAGE-1 fb_spike gate's exact
    frame expectation, reconstructed from fb_spike.rs's own constants. Same reason the
    font is parsed rather than transcribed.

`assert_not_flat` is here too, and is deliberately documented as what it is: a cheap
structural smoke check that ANY decorated frame satisfies. It is never a gate's only
pixel assertion — a title bar passes it, which is exactly why it stopped being one.
"""
from __future__ import annotations

import pathlib
import re

# The palette, copied from status_console/src/main.rs. These are 0xRRGGBB.
C_BG = 0x111820
C_LABEL = 0x8297A6
C_VALUE = 0xE8EEF2
C_SUBTLE = 0x90A4B4
C_DOWN = 0xE05555
C_UP = 0x45D07C
C_ACCENT = 0xF0C24A

# draw_char scales each 8x8 glyph bit to a scale x scale block; body text is scale 2.
SCALE = 2
# Labels in the right-hand column are padded to this width by Column::row, so the value
# begins exactly LABEL_CELLS glyphs after the label starts.
LABEL_CELLS = 10

_GLYPH_RE = re.compile(r"""b'(?P<ch>\\?.)'\s*=>\s*\[(?P<rows>[^\]]*)\],""")
_ROW_RE = re.compile(r"0[xX][0-9A-Fa-f_]+|0b[01_]+|\d+")
_REPEAT_RE = re.compile(r"(0[xXb][0-9A-Fa-f_]+|\d+)\s*;\s*(\d+)")
# Every character the panel's asserted rows are built from. If any of these stops being
# in the table the gate must fail loudly rather than quietly matching a hollow box.
REQUIRED_CHARS = set(" 0123456789.MiBGTKcoreslntzagupdvfwhxRFUSEDNAV%[]#-")


def load_font(font_rs: str | pathlib.Path) -> dict[str, list[int]]:
    """Parses the 8x8 glyph table out of the `glyph()` match in font.rs.

    Returns {char: [8 row bytes]}, MSB = leftmost column, matching `font::glyph`.

    Scoped to the body of `pub fn glyph`, not the whole file: an unrestricted whole-file
    scan would happily pick up a glyph-shaped literal in a comment or a second table and
    silently overwrite a real entry, giving a matcher that disagrees with the renderer
    while looking perfectly healthy. Duplicates are rejected for the same reason —
    Rust's first-match-wins and a dict's last-write-wins disagree, so a duplicate arm
    would mean the two sides had genuinely diverged.
    """
    text = pathlib.Path(font_rs).read_text()
    start = text.find("pub fn glyph")
    if start < 0:
        raise AssertionError(f"{font_rs} has no `pub fn glyph`; the renderer changed")
    body = text[start:]
    end = body.find("\n}")
    if end < 0:
        raise AssertionError(f"could not find the end of `glyph()` in {font_rs}")
    body = body[:end]
    # Strip comments so a commented-out or illustrative arm cannot enter the table.
    body = re.sub(r"//[^\n]*", "", body)

    font: dict[str, list[int]] = {}
    for m in _GLYPH_RE.finditer(body):
        ch = m.group("ch")
        if ch == "\\'":
            ch = "'"
        elif ch == "\\\\":
            ch = "\\"
        elif len(ch) != 1:
            continue
        raw = m.group("rows")
        # Rust's array-repeat form, `[v; 8]` — the space glyph is written `[0; 8]`.
        repeat = _REPEAT_RE.fullmatch(raw.strip())
        if repeat:
            value, count = int(repeat.group(1), 0), int(repeat.group(2), 0)
            if count != 8:
                raise AssertionError(f"glyph {ch!r} in {font_rs} repeats {count} rows, expected 8")
            rows = [value] * 8
        else:
            rows = [int(tok, 0) for tok in _ROW_RE.findall(raw)]
        if len(rows) != 8:
            raise AssertionError(f"glyph {ch!r} in {font_rs} has {len(rows)} rows, expected 8")
        if any(r > 0xFF for r in rows):
            raise AssertionError(f"glyph {ch!r} in {font_rs} has a row wider than 8 bits")
        if ch in font:
            raise AssertionError(
                f"glyph {ch!r} is defined twice in {font_rs}; Rust takes the first arm and "
                "this parser would take the last, so the two would disagree"
            )
        font[ch] = rows
    # The space is the single most load-bearing glyph here — every label is padded with
    # it and the full-cell comparison depends on it being genuinely blank.
    if font.get(" ") != [0] * 8:
        raise AssertionError(f"{font_rs} no longer defines the space glyph as 8 blank rows")
    missing = REQUIRED_CHARS - set(font)
    if missing:
        raise AssertionError(
            f"{font_rs} is missing glyphs the panel assertions need: {sorted(missing)!r}"
        )
    if len(font) < 60:
        raise AssertionError(
            f"parsed only {len(font)} glyphs from {font_rs}; the table format changed"
        )
    return font


def read_ppm(path: str | pathlib.Path) -> tuple[int, int, bytes]:
    """Reads a binary P6 PPM, validating the header and the exact payload length."""
    data = pathlib.Path(path).read_bytes()
    if not data.startswith(b"P6"):
        raise AssertionError(f"not a P6 PPM: {data[:16]!r}")
    idx, tokens = 2, []
    while len(tokens) < 3:
        while idx < len(data) and data[idx : idx + 1].isspace():
            idx += 1
        if idx < len(data) and data[idx : idx + 1] == b"#":
            while idx < len(data) and data[idx] != 0x0A:
                idx += 1
            continue
        start = idx
        while idx < len(data) and not data[idx : idx + 1].isspace():
            idx += 1
        tokens.append(data[start:idx])
    width, height, maxval = (int(t) for t in tokens)
    idx += 1  # exactly one whitespace byte separates the header from the payload
    if maxval != 255:
        raise AssertionError(f"PPM maxval {maxval}, expected 255 (one byte per channel)")
    if width <= 0 or height <= 0:
        raise AssertionError(f"degenerate PPM dims {width}x{height}")
    pixels = data[idx : idx + width * height * 3]
    if len(pixels) != width * height * 3:
        raise AssertionError(
            f"PPM truncated: {len(pixels)} payload bytes, expected {width * height * 3}"
        )
    return width, height, pixels


def _expected_cells(
    font: dict[str, list[int]], spans: list[tuple[str, int]], bg: int, scale: int
) -> list[tuple[int, int, int]]:
    """Flattens (text, colour) spans into [(dx, dy, rgb)] covering every pixel of every
    cell — set bits in the span's colour, clear bits in the background colour."""
    out: list[tuple[int, int, int]] = []
    cell = 0
    for text, color in spans:
        for ch in text:
            if ch not in font:
                raise AssertionError(
                    f"character {ch!r} has no glyph in font.rs; it would render as a box"
                )
            rows = font[ch]
            base_x = cell * 8 * scale
            for ry, bits in enumerate(rows):
                for rx in range(8):
                    rgb = color if (bits >> (7 - rx)) & 1 else bg
                    for sy in range(scale):
                        for sx in range(scale):
                            out.append(
                                (base_x + rx * scale + sx, ry * scale + sy, rgb)
                            )
            cell += 1
    # Order the checks so the first ones are the most discriminating: a foreground pixel
    # rejects ~every background position on the very first comparison, which is what keeps
    # a whole-framebuffer search tractable in Python.
    out.sort(key=lambda t: (t[2] == bg, t[1], t[0]))
    return out


def find_text(
    ppm: tuple[int, int, bytes],
    spans: list[tuple[str, int]],
    font: dict[str, list[int]],
    bg: int = C_BG,
    scale: int = SCALE,
) -> list[tuple[int, int]]:
    """All (x, y) origins where `spans` is drawn exactly, foreground and background."""
    width, height, pixels = ppm
    expected = _expected_cells(font, spans, bg, scale)
    span_w = max(dx for dx, _, _ in expected) + 1
    span_h = max(dy for _, dy, _ in expected) + 1
    if span_w > width or span_h > height:
        return []
    # Pre-split into byte triples once; indexing bytes three at a time in the inner loop
    # is what makes this too slow otherwise.
    checks = [
        (dy * width * 3 + dx * 3, bytes(((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF)))
        for dx, dy, rgb in expected
    ]
    matches: list[tuple[int, int]] = []
    row_bytes = width * 3
    for y in range(height - span_h + 1):
        row_base = y * row_bytes
        for x in range(width - span_w + 1):
            base = row_base + x * 3
            for off, want in checks:
                i = base + off
                if pixels[i : i + 3] != want:
                    break
            else:
                matches.append((x, y))
    return matches


def assert_panel_value(
    ppm: tuple[int, int, bytes],
    font: dict[str, list[int]],
    label: str,
    value: str,
    what: str,
    value_color: int = C_VALUE,
) -> tuple[int, int]:
    """Asserts the panel draws exactly one `label`/`value` row, and returns where.

    `label` is padded to LABEL_CELLS exactly as `Column::row` pads it, so the two spans
    are one contiguous run and the value's position is pinned by the label's.
    """
    if len(label) > LABEL_CELLS:
        raise AssertionError(f"label {label!r} longer than the column's {LABEL_CELLS} cells")
    spans = [(label.ljust(LABEL_CELLS), C_LABEL), (value, value_color)]
    hits = find_text(ppm, spans, font)
    if len(hits) != 1:
        raise AssertionError(
            f"{what}: expected exactly one on-screen row {label!r} = {value!r}, found "
            f"{len(hits)}{' at ' + str(hits) if hits else ''}. The value the console "
            f"logged is not the value it painted."
        )
    return hits[0]


def human_bytes(n: int) -> str:
    """Byte-for-byte the same formatting as metrics::human_bytes in the console.

    Deliberately reimplemented here rather than scraped from the console's own output:
    the point of the gate is that the HOST decides what the screen should say, from a raw
    number it validated independently. Searching for a string the console handed over
    would only prove the same string appeared in two places.
    """
    for div, unit in ((1 << 40, "TiB"), (1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")):
        if n >= div:
            return f"{n // div}.{(n % div) * 10 // div} {unit}"
    return f"{n} B"


def mib(n: int) -> str:
    """The console's `metrics::mib` rendering: whole MiB, truncated."""
    return f"{n // (1 << 20)} MiB"


# ---------------------------------------------------------------------------
# The cheap structural check, and an honest description of what it is worth.
# ---------------------------------------------------------------------------


def assert_not_flat(ppm: tuple[int, int, bytes], what: str = "screendump") -> int:
    """Asserts the frame is not one flat colour, and returns the distinct-colour count.

    WHAT THIS IS FOR. It is a smoke check with a clear message for a wholesale
    regression (nothing scanned out at all), and NOTHING MORE. Any decoration passes it:
    one title bar, one lit pixel, a colour gradient left over from firmware. It was
    every framebuffer gate's only pixel assertion once, and
    validation/framebuffer_assert_test.py now demonstrates, in-tree, a frame that this
    accepts and the real assertions reject. Never let it be a gate's only pixel claim.
    """
    width, height, pixels = ppm
    sample = pixels[: width * height * 3]
    first = sample[0:3]
    colours = {sample[i : i + 3] for i in range(0, len(sample), 3)}
    if len(colours) < 2:
        raise AssertionError(
            f"{what} is a single flat colour {first.hex()} ({width}x{height}): nothing "
            "reached the panel at all"
        )
    return len(colours)


# ---------------------------------------------------------------------------
# Panic patterns. The shared boot harness has had these since it was written
# (tests/zircon/zbi_boot_test.py:46); the standalone framebuffer harnesses never used
# them, so a boot that rendered, announced itself and then panicked left a perfectly
# varied framebuffer behind and passed.
# ---------------------------------------------------------------------------

PANIC_PATTERNS = ("KERNEL PANIC", "ZIRCON KERNEL PANIC", "triple fault", "KERNEL FAULT")


def assert_no_panic(text: str, what: str = "the boot") -> None:
    """Fails if the serial log contains a kernel panic anywhere in it.

    Called AFTER the success assertions and again after a settle, because the order the
    old harnesses used — accept on the first read that contains the success marker, then
    terminate — cannot see anything the guest flushes afterwards. A panic that arrives a
    second after the panel is painted is still a failed boot.
    """
    for pattern in PANIC_PATTERNS:
        if pattern in text:
            at = text.rfind(pattern)
            raise AssertionError(
                f"{what} panicked: {text[at:at + 400]!r}. The pixels on the panel do not "
                "make this a passing boot."
            )


# ---------------------------------------------------------------------------
# The console's evidence markers. One parser, shared by every gate that reads them.
# ---------------------------------------------------------------------------


def marker_lines(text: str, marker: str) -> list[dict[str, str]]:
    """Every LINE that is exactly this marker plus `key=value` fields, in order.

    Line-ANCHORED, not a substring search. An unanchored `rfind` would happily accept a
    marker name quoted inside some other component's error message and treat it as
    evidence; requiring the marker to start its own line and be followed only by
    well-formed fields does not.
    """
    out = []
    pattern = re.compile(rf"^{re.escape(marker)}:((?:\s+\w+=\S+)*)\s*$")
    for raw in text.replace("\r", "\n").split("\n"):
        m = pattern.match(raw.strip())
        if m:
            out.append(dict(re.findall(r"(\w+)=(\S+)", m.group(1))))
    return out


def metric_settled(text: str, family: str) -> tuple[dict[str, str] | None, str]:
    """Is the LATEST word on `family` an -OK, and if so with what fields?

    Every metric starts out honestly unavailable — CPU utilisation needs two samples, and
    the file server has not surveyed the disk until ~a minute into boot — so the log
    legitimately contains -UNAVAILABLE lines from early paints. What matters is the state
    the panel has SETTLED into, which is whichever of the two markers was emitted last.
    Treating any historical -UNAVAILABLE as fatal would fail every boot; ignoring them
    entirely would let a metric that went unavailable and stayed there slip through. So:
    compare positions, of ANCHORED lines only.
    """
    ok_marker = f"CERISE-CONSOLE-{family}-OK"
    bad_marker = f"CERISE-CONSOLE-{family}-UNAVAILABLE"
    lines = text.replace("\r", "\n").split("\n")
    ok_at, bad_at, fields = -1, -1, None
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith(bad_marker + ":"):
            bad_at = i
        m = re.match(rf"^{re.escape(ok_marker)}:((?:\s+\w+=\S+)*)\s*$", stripped)
        if m:
            ok_at = i
            fields = dict(re.findall(r"(\w+)=(\S+)", m.group(1)))
    if ok_at < 0 or bad_at > ok_at:
        reason = lines[bad_at].strip() if bad_at >= 0 else ""
        return None, reason
    if not fields:
        return None, f"{ok_marker} carried no fields"
    return fields, ""


def last_marker(text: str, marker: str) -> dict[str, str]:
    """The fields of the LAST well-formed occurrence of a marker line.

    Last, not first: the console re-emits when a value's stable identity changes, so the
    final line is the one describing the panel as it stands now. A missing marker is an
    error rather than an empty dict — silently treating "never emitted" as "no fields"
    is how a gate ends up asserting nothing.
    """
    lines = marker_lines(text, marker)
    if not lines:
        raise AssertionError(f"guest never emitted a well-formed {marker} line")
    return lines[-1]


def int_field(fields: dict[str, str], name: str, marker: str) -> int:
    raw = fields.get(name)
    if raw is None:
        raise AssertionError(f"{marker} has no {name}= field: {fields}")
    try:
        return int(raw)
    except ValueError:
        raise AssertionError(f"{marker} {name}={raw!r} is not an integer") from None


# ---------------------------------------------------------------------------
# initial prototype (fb_spike): the exact frame the driverless framebuffer must scan out.
# ---------------------------------------------------------------------------

# The paint, as fb_spike.rs's `main` writes it. Mirrored here rather than interpreted,
# and pinned to the source text below so the mirror cannot silently stop describing it.
_SPIKE_LETS = [
    ("third", "WIDTH / 3"),
    ("bar_y", "HEIGHT * 2 / 3"),
    ("bar_h", "HEIGHT - bar_y"),
    ("pw", "WIDTH / 2"),
    ("ph", "HEIGHT / 3"),
    ("px", "(WIDTH - pw) / 2"),
    ("py", "HEIGHT / 6"),
]
_SPIKE_FILLS = [
    "0, bar_y, third, bar_h, BAR_R",
    "third, bar_y, third, bar_h, BAR_G",
    "2 * third, bar_y, WIDTH - 2 * third, bar_h, BAR_B",
    "px, py, pw, ph, PANEL",
    "px + 16, py + 16, pw - 32, ph - 32, BG",
]
_SPIKE_CONSTS = ("WIDTH", "HEIGHT", "BG", "BAR_R", "BAR_G", "BAR_B", "PANEL")


def _rust_consts(path: pathlib.Path, names: tuple[str, ...]) -> dict[str, int]:
    text = path.read_text()
    out: dict[str, int] = {}
    for name in names:
        m = re.search(rf"^const\s+{name}\s*:\s*\w+\s*=\s*([0-9A-Fa-fxX_]+)\s*;", text, re.M)
        if not m:
            raise AssertionError(f"{path} no longer defines `const {name}`")
        out[name] = int(m.group(1).replace("_", ""), 0)
    return out


def expected_spike_frame(fb_spike_rs: str | pathlib.Path) -> tuple[int, int, bytes]:
    """Rebuilds, byte for byte, the frame fb_spike.rs paints — from fb_spike.rs itself.

    WHY EXACT AND WHY RECONSTRUCTED. The old assertion was "the screendump contains more
    than one colour", which the guest could satisfy by painting a single stripe and which
    a VGA device could satisfy on its own. This asserts the whole 1024x768 surface: the
    background, three bars in three specific colours in three specific thirds of the
    bottom third, an amber panel of a specific size in a specific place, and a background-
    coloured inset 16px inside it. There is no cheaper way to satisfy that than to bring
    the framebuffer up and paint it.

    The colours and the mode come from the guest's own source, so a change there cannot
    leave the matcher describing a frame nobody draws. The LAYOUT is mirrored in Python —
    it has to be, something has to say what the picture should look like — so the mirror
    is pinned to the source's own call text: change the paint and this fails loudly
    saying so, rather than producing a pixel diff nobody can read.
    """
    path = pathlib.Path(fb_spike_rs)
    src = path.read_text()
    body_start = src.find("fn main()")
    if body_start < 0:
        raise AssertionError(f"{path} has no `fn main()`; the spike changed shape")
    body = src[body_start:]
    body = re.sub(r"//[^\n]*", "", body)

    clears = re.findall(r"fb\.clear\(\s*(\w+)\s*\)", body)
    if clears != ["BG"]:
        raise AssertionError(
            f"{path}'s main() clears the framebuffer with {clears!r}, expected exactly "
            "one clear(BG); this expectation mirrors the paint and must be updated"
        )
    lets = [
        (m.group(1), " ".join(m.group(2).split()))
        for m in re.finditer(r"let\s+(\w+)\s*=\s*([^;]+);", body)
    ]
    lets = [lv for lv in lets if lv[0] in dict(_SPIKE_LETS)]
    if lets != _SPIKE_LETS:
        raise AssertionError(
            f"{path}'s geometry bindings are {lets!r}, expected {_SPIKE_LETS!r}; the "
            "spike's layout changed and this expectation must be updated with it"
        )
    fills = [
        " ".join(m.group(1).split())
        for m in re.finditer(r"fb\.fill_rect\(([^;]*)\)\s*;", body)
    ]
    if fills != _SPIKE_FILLS:
        raise AssertionError(
            f"{path}'s main() paints {len(fills)} rect(s):\n  "
            + "\n  ".join(fills)
            + "\nexpected:\n  "
            + "\n  ".join(_SPIKE_FILLS)
            + "\nThe spike's pattern changed; update this expectation to match it."
        )

    c = _rust_consts(path, _SPIKE_CONSTS)
    width, height = c["WIDTH"], c["HEIGHT"]
    # SOURCE-INDEPENDENT FLOOR. Everything above is read out of the guest's own source,
    # which means a change there moves BOTH sides together: shrink the mode to 8x8 and
    # collapse the palette to one colour and the "exact frame" assertion is satisfied by
    # a guest that clears the screen once. These invariants are stated HERE, by the gate,
    # so the two sides cannot co-degenerate.
    if not (1024 <= width <= 4096 and 768 <= height <= 4096):
        raise AssertionError(
            f"spike mode {width}x{height} is below the 1024x768 this gate requires; a "
            "smaller mode makes the exact-frame assertion trivially satisfiable"
        )
    palette = {name: c[name] for name in ("BG", "BAR_R", "BAR_G", "BAR_B", "PANEL")}
    if len(set(palette.values())) != len(palette):
        raise AssertionError(
            f"the spike's five colours are not pairwise distinct: "
            f"{ {k: hex(v) for k, v in palette.items()} }. Collapsing two of them turns "
            "a five-region picture into a picture a single fill could paint."
        )

    def rgb(value: int) -> bytes:
        return bytes(((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF))

    frame = bytearray(rgb(c["BG"]) * (width * height))

    def fill(x: int, y: int, w: int, h: int, colour: int) -> None:
        if x < 0 or y < 0 or x + w > width or y + h > height or w <= 0 or h <= 0:
            raise AssertionError(f"spike rect {x},{y} {w}x{h} does not fit {width}x{height}")
        row = rgb(colour) * w
        for yy in range(y, y + h):
            off = (yy * width + x) * 3
            frame[off : off + w * 3] = row

    third = width // 3
    bar_y = height * 2 // 3
    bar_h = height - bar_y
    fill(0, bar_y, third, bar_h, c["BAR_R"])
    fill(third, bar_y, third, bar_h, c["BAR_G"])
    fill(2 * third, bar_y, width - 2 * third, bar_h, c["BAR_B"])
    pw, ph = width // 2, height // 3
    px, py = (width - pw) // 2, height // 6
    fill(px, py, pw, ph, c["PANEL"])
    fill(px + 16, py + 16, pw - 32, ph - 32, c["BG"])
    # And the picture the layout actually produced must still be a picture: every colour
    # present over a real area, so no arrangement of the (already distinct) constants can
    # reduce the expected frame to something one fill_rect would satisfy.
    counts = {name: 0 for name in palette}
    by_rgb = {rgb(v): k for k, v in palette.items()}
    for i in range(0, len(frame), 3):
        name = by_rgb.get(bytes(frame[i : i + 3]))
        if name is not None:
            counts[name] += 1
    total = width * height
    thin = {k: v for k, v in counts.items() if v < total // 100}
    if thin:
        raise AssertionError(
            f"the expected frame gives {thin} fewer than 1% of its pixels each (of "
            f"{total}); the spike's pattern has degenerated into one a single fill could "
            "paint, and the exact-frame assertion would no longer discriminate"
        )
    return width, height, bytes(frame)


def assert_frame_matches(
    ppm: tuple[int, int, bytes], expected: tuple[int, int, bytes], what: str
) -> None:
    """Asserts a captured frame is EXACTLY the expected one, with a readable diagnosis."""
    ew, eh, epix = expected
    gw, gh, gpix = ppm
    if (gw, gh) != (ew, eh):
        raise AssertionError(
            f"{what}: captured {gw}x{gh}, expected {ew}x{eh}. The guest set a mode the "
            "harness does not know about, or nothing set one."
        )
    gpix = gpix[: ew * eh * 3]
    if gpix == epix:
        return
    bad = 0
    first = None
    hist: dict[bytes, int] = {}
    for i in range(0, len(epix), 3):
        got, want = gpix[i : i + 3], epix[i : i + 3]
        if got != want:
            bad += 1
            if first is None:
                px = (i // 3) % ew
                py = (i // 3) // ew
                first = (px, py, got.hex(), want.hex())
        hist[got] = hist.get(got, 0) + 1
    top = sorted(hist.items(), key=lambda kv: -kv[1])[:5]
    raise AssertionError(
        f"{what}: {bad} of {ew * eh} pixels ({100.0 * bad / (ew * eh):.2f}%) differ from "
        f"the pattern the guest's own source says it paints. First difference at "
        f"x={first[0]} y={first[1]}: got #{first[2]}, expected #{first[3]}. Most common "
        f"colours actually on the panel: "
        + ", ".join(f"#{c.hex()}x{n}" for c, n in top)
    )
