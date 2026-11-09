// Copyright 2026 The Cerise Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// This file is compiled into BOTH physboot and the kernel proper, so it must
// not depend on anything specific to either: no PhysConsole, no dprintf, no
// allocation.  The stage-specific wiring lives in framebuffer-console-zbi.cc
// (physboot) and //zircon/kernel/lib/io/framebuffer-console.cc (the kernel).

#include <phys/framebuffer-console.h>

#include <stdint.h>

#include <ktl/algorithm.h>
#include <ktl/iterator.h>
#include <ktl/optional.h>
#include <ktl/utility.h>

#include <ktl/enforce.h>

namespace {

// An 8x8 bitmap font covering all of printable ASCII, 0x20 through 0x7e.  Each
// glyph is eight rows, most significant bit leftmost.  The face occupies the
// left six columns and the top seven rows, so the spare column pair and bottom
// row keep adjacent cells from touching without needing any inter-cell gap.
//
// The rows are written as binary literals so each glyph is legible in-source
// and can be corrected by eye, matching the convention already used by
// //src/cerise/status_console/src/font.rs.
using Glyph = uint8_t[FramebufferConsole::kGlyphHeight];

constexpr Glyph kFont[] = {
    {0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000},  // 0x20 'space'
    {0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00000000, 0b00110000, 0b00000000},  // 0x21 '!'
    {0b01101100, 0b01101100, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000},  // 0x22 '"'
    {0b01101100, 0b01101100, 0b11111110, 0b01101100, 0b11111110, 0b01101100, 0b01101100, 0b00000000},  // 0x23 '#'
    {0b00110000, 0b01111100, 0b11000000, 0b01111000, 0b00000011, 0b11111000, 0b00110000, 0b00000000},  // 0x24 '$'
    {0b11000110, 0b11001100, 0b00011000, 0b00110000, 0b01100110, 0b11000110, 0b00000000, 0b00000000},  // 0x25 '%'
    {0b01110000, 0b11011000, 0b00110000, 0b01101100, 0b11001100, 0b11001100, 0b01110110, 0b00000000},  // 0x26 '&'
    {0b00110000, 0b00110000, 0b00110000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000},  // 0x27 '''
    {0b00011000, 0b00110000, 0b01100000, 0b01100000, 0b01100000, 0b00110000, 0b00011000, 0b00000000},  // 0x28 '('
    {0b01100000, 0b00110000, 0b00011000, 0b00011000, 0b00011000, 0b00110000, 0b01100000, 0b00000000},  // 0x29 ')'
    {0b00000000, 0b11000110, 0b01101100, 0b11111110, 0b01101100, 0b11000110, 0b00000000, 0b00000000},  // 0x2a '*'
    {0b00000000, 0b00110000, 0b00110000, 0b11111100, 0b00110000, 0b00110000, 0b00000000, 0b00000000},  // 0x2b '+'
    {0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00110000, 0b00110000, 0b00110000},  // 0x2c ','
    {0b00000000, 0b00000000, 0b00000000, 0b11111100, 0b00000000, 0b00000000, 0b00000000, 0b00000000},  // 0x2d '-'
    {0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00110000, 0b00110000, 0b00000000},  // 0x2e '.'
    {0b00000011, 0b00000110, 0b00001100, 0b00011000, 0b00110000, 0b01100000, 0b11000000, 0b00000000},  // 0x2f '/'
    {0b01111000, 0b11001100, 0b11011100, 0b11111000, 0b11100110, 0b11000110, 0b01111000, 0b00000000},  // 0x30 '0'
    {0b00110000, 0b01110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b11111100, 0b00000000},  // 0x31 '1'
    {0b01111000, 0b11001100, 0b00001100, 0b00011000, 0b00110000, 0b01100000, 0b11111100, 0b00000000},  // 0x32 '2'
    {0b01111000, 0b11001100, 0b00001100, 0b00111000, 0b00001100, 0b11001100, 0b01111000, 0b00000000},  // 0x33 '3'
    {0b00011100, 0b00111100, 0b01101100, 0b11001100, 0b11111100, 0b00001100, 0b00001100, 0b00000000},  // 0x34 '4'
    {0b11111100, 0b11000000, 0b11111000, 0b00001100, 0b00001100, 0b11001100, 0b01111000, 0b00000000},  // 0x35 '5'
    {0b00111000, 0b01100000, 0b11000000, 0b11111000, 0b11001100, 0b11001100, 0b01111000, 0b00000000},  // 0x36 '6'
    {0b11111100, 0b11001100, 0b00001100, 0b00011000, 0b00110000, 0b00110000, 0b00110000, 0b00000000},  // 0x37 '7'
    {0b01111000, 0b11001100, 0b11001100, 0b01111000, 0b11001100, 0b11001100, 0b01111000, 0b00000000},  // 0x38 '8'
    {0b01111000, 0b11001100, 0b11001100, 0b01111100, 0b00001100, 0b00011000, 0b01110000, 0b00000000},  // 0x39 '9'
    {0b00000000, 0b00110000, 0b00110000, 0b00000000, 0b00000000, 0b00110000, 0b00110000, 0b00000000},  // 0x3a ':'
    {0b00000000, 0b00110000, 0b00110000, 0b00000000, 0b00000000, 0b00110000, 0b00110000, 0b00110000},  // 0x3b ';'
    {0b00001100, 0b00011000, 0b00110000, 0b01100000, 0b00110000, 0b00011000, 0b00001100, 0b00000000},  // 0x3c '<'
    {0b00000000, 0b00000000, 0b11111100, 0b00000000, 0b11111100, 0b00000000, 0b00000000, 0b00000000},  // 0x3d '='
    {0b01100000, 0b00110000, 0b00011000, 0b00001100, 0b00011000, 0b00110000, 0b01100000, 0b00000000},  // 0x3e '>'
    {0b01111000, 0b11001100, 0b00001100, 0b00011000, 0b00110000, 0b00000000, 0b00110000, 0b00000000},  // 0x3f '?'
    {0b01111000, 0b11001100, 0b11011100, 0b11011100, 0b11000000, 0b11000000, 0b01111000, 0b00000000},  // 0x40 '@'
    {0b00110000, 0b01111000, 0b11001100, 0b11001100, 0b11111100, 0b11001100, 0b11001100, 0b00000000},  // 0x41 'A'
    {0b11111000, 0b11001100, 0b11001100, 0b11111000, 0b11001100, 0b11001100, 0b11111000, 0b00000000},  // 0x42 'B'
    {0b01111000, 0b11001100, 0b11000000, 0b11000000, 0b11000000, 0b11001100, 0b01111000, 0b00000000},  // 0x43 'C'
    {0b11110000, 0b11011000, 0b11001100, 0b11001100, 0b11001100, 0b11011000, 0b11110000, 0b00000000},  // 0x44 'D'
    {0b11111100, 0b11000000, 0b11000000, 0b11111000, 0b11000000, 0b11000000, 0b11111100, 0b00000000},  // 0x45 'E'
    {0b11111100, 0b11000000, 0b11000000, 0b11111000, 0b11000000, 0b11000000, 0b11000000, 0b00000000},  // 0x46 'F'
    {0b01111000, 0b11001100, 0b11000000, 0b11011100, 0b11001100, 0b11001100, 0b01111000, 0b00000000},  // 0x47 'G'
    {0b11001100, 0b11001100, 0b11001100, 0b11111100, 0b11001100, 0b11001100, 0b11001100, 0b00000000},  // 0x48 'H'
    {0b11111100, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b11111100, 0b00000000},  // 0x49 'I'
    {0b00011100, 0b00001100, 0b00001100, 0b00001100, 0b11001100, 0b11001100, 0b01111000, 0b00000000},  // 0x4a 'J'
    {0b11001100, 0b11011000, 0b11110000, 0b11100000, 0b11110000, 0b11011000, 0b11001100, 0b00000000},  // 0x4b 'K'
    {0b11000000, 0b11000000, 0b11000000, 0b11000000, 0b11000000, 0b11000000, 0b11111100, 0b00000000},  // 0x4c 'L'
    {0b11000110, 0b11101110, 0b11111110, 0b11010110, 0b11000110, 0b11000110, 0b11000110, 0b00000000},  // 0x4d 'M'
    {0b11001100, 0b11101100, 0b11111100, 0b11111100, 0b11011100, 0b11001100, 0b11001100, 0b00000000},  // 0x4e 'N'
    {0b01111000, 0b11001100, 0b11001100, 0b11001100, 0b11001100, 0b11001100, 0b01111000, 0b00000000},  // 0x4f 'O'
    {0b11111000, 0b11001100, 0b11001100, 0b11111000, 0b11000000, 0b11000000, 0b11000000, 0b00000000},  // 0x50 'P'
    {0b01111000, 0b11001100, 0b11001100, 0b11001100, 0b11011100, 0b11011000, 0b01101100, 0b00000000},  // 0x51 'Q'
    {0b11111000, 0b11001100, 0b11001100, 0b11111000, 0b11110000, 0b11011000, 0b11001100, 0b00000000},  // 0x52 'R'
    {0b01111000, 0b11001100, 0b11000000, 0b01111000, 0b00001100, 0b11001100, 0b01111000, 0b00000000},  // 0x53 'S'
    {0b11111100, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00000000},  // 0x54 'T'
    {0b11001100, 0b11001100, 0b11001100, 0b11001100, 0b11001100, 0b11001100, 0b01111000, 0b00000000},  // 0x55 'U'
    {0b11001100, 0b11001100, 0b11001100, 0b11001100, 0b11001100, 0b01111000, 0b00110000, 0b00000000},  // 0x56 'V'
    {0b11000110, 0b11000110, 0b11000110, 0b11010110, 0b11111110, 0b11101110, 0b11000110, 0b00000000},  // 0x57 'W'
    {0b11001100, 0b11001100, 0b01111000, 0b00110000, 0b01111000, 0b11001100, 0b11001100, 0b00000000},  // 0x58 'X'
    {0b11001100, 0b11001100, 0b11001100, 0b01111000, 0b00110000, 0b00110000, 0b00110000, 0b00000000},  // 0x59 'Y'
    {0b11111100, 0b00001100, 0b00011000, 0b00110000, 0b01100000, 0b11000000, 0b11111100, 0b00000000},  // 0x5a 'Z'
    {0b00111100, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00111100, 0b00000000},  // 0x5b '['
    {0b11000000, 0b01100000, 0b00110000, 0b00011000, 0b00001100, 0b00000110, 0b00000011, 0b00000000},  // 0x5c '\'
    {0b11110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b11110000, 0b00000000},  // 0x5d ']'
    {0b00110000, 0b01111000, 0b11001100, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000},  // 0x5e '^'
    {0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b11111110},  // 0x5f '_'
    {0b01100000, 0b00110000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000},  // 0x60 '`'
    {0b00000000, 0b00000000, 0b01111000, 0b00001100, 0b01111100, 0b11001100, 0b01111100, 0b00000000},  // 0x61 'a'
    {0b11000000, 0b11000000, 0b11111000, 0b11001100, 0b11001100, 0b11001100, 0b11111000, 0b00000000},  // 0x62 'b'
    {0b00000000, 0b00000000, 0b01111000, 0b11001100, 0b11000000, 0b11001100, 0b01111000, 0b00000000},  // 0x63 'c'
    {0b00001100, 0b00001100, 0b01111100, 0b11001100, 0b11001100, 0b11001100, 0b01111100, 0b00000000},  // 0x64 'd'
    {0b00000000, 0b00000000, 0b01111000, 0b11001100, 0b11111100, 0b11000000, 0b01111000, 0b00000000},  // 0x65 'e'
    {0b00111000, 0b01101100, 0b01100000, 0b11111000, 0b01100000, 0b01100000, 0b01100000, 0b00000000},  // 0x66 'f'
    {0b00000000, 0b01111100, 0b11001100, 0b11001100, 0b01111100, 0b00001100, 0b01111000, 0b00000000},  // 0x67 'g'
    {0b11000000, 0b11000000, 0b11111000, 0b11001100, 0b11001100, 0b11001100, 0b11001100, 0b00000000},  // 0x68 'h'
    {0b00110000, 0b00000000, 0b01110000, 0b00110000, 0b00110000, 0b00110000, 0b01111000, 0b00000000},  // 0x69 'i'
    {0b00001100, 0b00000000, 0b00011100, 0b00001100, 0b00001100, 0b11001100, 0b01111000, 0b00000000},  // 0x6a 'j'
    {0b11000000, 0b11000000, 0b11001100, 0b11011000, 0b11110000, 0b11011000, 0b11001100, 0b00000000},  // 0x6b 'k'
    {0b01110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b01111000, 0b00000000},  // 0x6c 'l'
    {0b00000000, 0b00000000, 0b11011000, 0b11111110, 0b11010110, 0b11010110, 0b11000110, 0b00000000},  // 0x6d 'm'
    {0b00000000, 0b00000000, 0b11111000, 0b11001100, 0b11001100, 0b11001100, 0b11001100, 0b00000000},  // 0x6e 'n'
    {0b00000000, 0b00000000, 0b01111000, 0b11001100, 0b11001100, 0b11001100, 0b01111000, 0b00000000},  // 0x6f 'o'
    {0b00000000, 0b11111000, 0b11001100, 0b11001100, 0b11111000, 0b11000000, 0b11000000, 0b00000000},  // 0x70 'p'
    {0b00000000, 0b01111100, 0b11001100, 0b11001100, 0b01111100, 0b00001100, 0b00001100, 0b00000000},  // 0x71 'q'
    {0b00000000, 0b00000000, 0b11011100, 0b11100110, 0b11000000, 0b11000000, 0b11000000, 0b00000000},  // 0x72 'r'
    {0b00000000, 0b00000000, 0b01111100, 0b11000000, 0b01111000, 0b00001100, 0b11111000, 0b00000000},  // 0x73 's'
    {0b01100000, 0b01100000, 0b11111000, 0b01100000, 0b01100000, 0b01101100, 0b00111000, 0b00000000},  // 0x74 't'
    {0b00000000, 0b00000000, 0b11001100, 0b11001100, 0b11001100, 0b11001100, 0b01111100, 0b00000000},  // 0x75 'u'
    {0b00000000, 0b00000000, 0b11001100, 0b11001100, 0b11001100, 0b01111000, 0b00110000, 0b00000000},  // 0x76 'v'
    {0b00000000, 0b00000000, 0b11000110, 0b11010110, 0b11010110, 0b11111110, 0b01101100, 0b00000000},  // 0x77 'w'
    {0b00000000, 0b00000000, 0b11001100, 0b01111000, 0b00110000, 0b01111000, 0b11001100, 0b00000000},  // 0x78 'x'
    {0b00000000, 0b11001100, 0b11001100, 0b11001100, 0b01111100, 0b00001100, 0b01111000, 0b00000000},  // 0x79 'y'
    {0b00000000, 0b00000000, 0b11111100, 0b00011000, 0b00110000, 0b01100000, 0b11111100, 0b00000000},  // 0x7a 'z'
    {0b00011100, 0b00110000, 0b00110000, 0b01100000, 0b00110000, 0b00110000, 0b00011100, 0b00000000},  // 0x7b '{'
    {0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00110000, 0b00000000},  // 0x7c '|'
    {0b11100000, 0b00110000, 0b00110000, 0b00011000, 0b00110000, 0b00110000, 0b11100000, 0b00000000},  // 0x7d '}'
    {0b01100110, 0b11011011, 0b11000110, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000},  // 0x7e '~'
};

constexpr char kFirstGlyph = 0x20;
constexpr char kLastGlyph = 0x7e;
static_assert(ktl::size(kFont) == kLastGlyph - kFirstGlyph + 1);

// Anything unprintable draws as a filled block rather than a blank, so that
// unexpected bytes are visible instead of silently vanishing.
constexpr Glyph kUnknownGlyph = {0b00000000, 0b01111100, 0b01111100, 0b01111100,
                                 0b01111100, 0b01111100, 0b00000000, 0b00000000};

const uint8_t* GlyphFor(char c) {
  if (c >= kFirstGlyph && c <= kLastGlyph) {
    return kFont[c - kFirstGlyph];
  }
  return kUnknownGlyph;
}

FramebufferConsole gFramebufferConsole;

}  // namespace

FramebufferConsole& GetFramebufferConsole() { return gFramebufferConsole; }

bool FramebufferConsole::Init(const zbi_swfb_t& fb) {
  return Init(fb, reinterpret_cast<void*>(static_cast<uintptr_t>(fb.base)));
}

bool FramebufferConsole::Init(const zbi_swfb_t& fb, void* mapped_base) {
  // Every rejection below is a normal condition: the caller carries on with
  // whatever console it already had.
  if (mapped_base == nullptr || fb.base == 0 || fb.width == 0 || fb.height == 0 ||
      fb.stride < fb.width) {
    return false;
  }

  // Only the two 32-bit formats are supported.  RGB_565 and anything else
  // means no framebuffer console rather than a wrongly-coloured one.  Both
  // supported formats agree on the encoding of black and white, which is all
  // this console draws, so no per-format encoding is needed.
  switch (fb.format) {
    case ZBI_PIXEL_FORMAT_ARGB_8888:
    case ZBI_PIXEL_FORMAT_ABGR_8888:
      break;
    default:
      return false;
  }

  // Magnify on large panels so the text stays about 120 columns wide and
  // remains readable on a physical screen (and in a remote screenshot).
  const uint32_t scale = fb.width >= 1280 ? 2 : 1;
  const uint32_t columns = fb.width / (kGlyphWidth * scale);
  const uint32_t rows = fb.height / (kGlyphHeight * scale);
  if (columns == 0 || rows == 0) {
    return false;
  }

  pixels_ = reinterpret_cast<volatile uint32_t*>(mapped_base);
  width_ = fb.width;
  height_ = fb.height;
  stride_ = fb.stride;
  scale_ = scale;
  columns_ = columns;
  rows_ = rows;
  col_ = row_ = top_row_ = 0;
  fg_ = 0xffffffff;
  bg_ = 0xff000000;

  // Clear the whole panel.  This is deliberate and load-bearing: it wipes the
  // boot loader's text, so a panel that goes black and then shows kernel
  // output proves physboot got this far, while a panel still showing the boot
  // shim's last line proves it did not.  That distinction is the entire reason
  // this console exists.  The clear is write-only, so it stays fast even on a
  // write-combining framebuffer.
  ClearRows(0, height_);
  return true;
}

ktl::optional<uart::MmioRange> FramebufferConsole::maybe_mmio_range() const {
  if (!active()) {
    return ktl::nullopt;
  }
  return uart::MmioRange{
      .address = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(pixels_)),
      .size = uint64_t{stride_} * height_ * kBytesPerPixel,
  };
}

void FramebufferConsole::Disable() { pixels_ = nullptr; }

void FramebufferConsole::FillRows(uint32_t y, uint32_t rows, uint32_t color) {
  const uint32_t end = ktl::min(y + rows, height_);
  for (uint32_t line = y; line < end; ++line) {
    volatile uint32_t* p = pixels_ + (size_t{line} * stride_);
    for (uint32_t x = 0; x < width_; ++x) {
      p[x] = color;
    }
  }
}

void FramebufferConsole::ClearRows(uint32_t y, uint32_t rows) { FillRows(y, rows, bg_); }

void FramebufferConsole::Banner(ktl::string_view text) {
  if (!active() || rows_ < 2) {
    // With only one text row there is nothing to reserve a row from: a banner
    // would leave nowhere for the output it is meant to label.
    return;
  }

  // Inverse video: a solid bar of foreground with background-coloured glyphs
  // on it.  PutChar only ever writes fg_, leaving the rest alone, so swapping
  // fg_ for the duration paints the text and nothing else.
  const uint32_t cell = kGlyphHeight * scale_;
  FillRows(0, cell, fg_);
  const uint32_t text_colour = ktl::exchange(fg_, bg_);
  col_ = 0;
  row_ = 0;
  for (char c : text) {
    if (col_ >= columns_) {
      break;  // A banner is exactly one row; never wrap it onto the log.
    }
    PutChar(c);
  }
  fg_ = text_colour;

  // Refill the bottom scanline of the cell, under the text.  It reads as an
  // underline, and it is also what makes the banner measurable: whatever the
  // text says, the row is then guaranteed to contain at least one completely
  // lit scanline.  No glyph in the font has a full row of ink and every cell
  // has gaps, so a completely lit scanline cannot come from text -- which is
  // what lets //validation:firstlight-uefi-boot tell the kernel's console from
  // physboot's in pixels alone, rather than by a threshold that a long enough
  // line of text could creep past.
  FillRows(cell - scale_, scale_, fg_);

  // Reserve the row and start the log below it.
  top_row_ = 1;
  col_ = 0;
  row_ = 1;
  ClearRows(row_ * cell, cell * 2);
}

void FramebufferConsole::Scroll() {
  // The cursor wraps to the top instead of scrolling the image.  Scrolling
  // would mean reading back the whole framebuffer, and reads from an
  // uncached/write-combining framebuffer are slow enough (megabytes per
  // scrolled line) that a chatty log would look like a hang -- the exact
  // failure mode this console is meant to diagnose.  Wrapping only ever
  // writes.  The blank tear line cleared below marks where output resumes, so
  // the newest text is still easy to find.  Wrapping to top_row_ rather than
  // to 0 is what keeps a Banner() row from ever being overwritten.
  row_ = top_row_;
}

void FramebufferConsole::Newline() {
  col_ = 0;
  if (++row_ >= rows_) {
    Scroll();
  }
  // Clear the line about to be written plus one more, leaving a blank gap
  // ahead of the cursor that shows the reader where the newest output ends.
  const uint32_t cell = kGlyphHeight * scale_;
  ClearRows(row_ * cell, cell * 2);
}

void FramebufferConsole::PutChar(char c) {
  if (col_ >= columns_) {
    Newline();
  }

  const uint8_t* glyph = GlyphFor(c);
  const uint32_t x0 = col_ * kGlyphWidth * scale_;
  const uint32_t y0 = row_ * kGlyphHeight * scale_;

  for (uint32_t gy = 0; gy < kGlyphHeight; ++gy) {
    const uint8_t bits = glyph[gy];
    for (uint32_t sy = 0; sy < scale_; ++sy) {
      const uint32_t y = y0 + gy * scale_ + sy;
      if (y >= height_) {
        return;
      }
      volatile uint32_t* line = pixels_ + (size_t{y} * stride_);
      for (uint32_t gx = 0; gx < kGlyphWidth; ++gx) {
        if ((bits & (0x80u >> gx)) == 0) {
          continue;  // The background is already clear.
        }
        for (uint32_t sx = 0; sx < scale_; ++sx) {
          const uint32_t x = x0 + gx * scale_ + sx;
          if (x < width_) {
            line[x] = fg_;
          }
        }
      }
    }
  }
  ++col_;
}

int FramebufferConsole::Write(ktl::string_view str) {
  if (!active()) {
    return static_cast<int>(str.size());
  }
  for (char c : str) {
    switch (c) {
      case '\n':
        Newline();
        break;
      case '\r':
        col_ = 0;
        break;
      case '\t':
        do {
          PutChar(' ');
        } while (col_ % 8 != 0 && col_ < columns_);
        break;
      default:
        // Drop the remaining control characters: this console has no escape
        // sequence handling, and drawing them would be noise.
        if (c >= kFirstGlyph) {
          PutChar(c);
        }
        break;
    }
  }
  // Always report full success.  A console that cannot draw must not make the
  // caller retry or fail; losing a character is strictly better than stalling.
  return static_cast<int>(str.size());
}
