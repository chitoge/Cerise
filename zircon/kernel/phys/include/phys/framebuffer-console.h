// Copyright 2026 The Cerise Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_PHYS_INCLUDE_PHYS_FRAMEBUFFER_CONSOLE_H_
#define ZIRCON_KERNEL_PHYS_INCLUDE_PHYS_FRAMEBUFFER_CONSOLE_H_

#include <lib/uart/uart.h>
#include <lib/zbi-format/graphics.h>
#include <stdint.h>

#include <ktl/optional.h>
#include <ktl/string_view.h>

// A minimal text console that renders into the linear framebuffer the boot
// loader handed over in a ZBI_TYPE_FRAMEBUFFER item.
//
// This exists because a machine whose UART does not work has no other way to
// show early kernel output: nothing between the boot shim's last line and
// userspace coming up draws anything to the panel.  It is deliberately
// featureless -- one colour, one font, newline and scroll, no cursor and no
// escape sequences -- because its whole job is to make a silent freeze into a
// readable log.
//
// It is always safe to have no framebuffer.  Init() simply reports false and
// every other entry point becomes a no-op, so serial-only boots (QEMU and
// every board that is not the panel-only case) behave exactly as before.
//
// The class is shared verbatim by physboot and by the kernel proper: the two
// have entirely separate consoles (separate binaries, separate instances of
// the singleton below), but a single renderer, so the panel looks the same
// before and after the hand-off and there is only one font to maintain.  The
// only thing the kernel needs that physboot does not is the Init() overload
// taking an explicit mapped address, since after the hand-off the framebuffer
// is no longer identity mapped.
class FramebufferConsole {
 public:
  // The embedded font's glyph cell, before scaling.
  static constexpr uint32_t kGlyphWidth = 8;
  static constexpr uint32_t kGlyphHeight = 8;

  // Takes on the framebuffer described by `fb`, clears it and starts at the
  // top left.  Returns false and leaves the object inactive if the item is
  // unusable: a null base, a degenerate geometry, a stride narrower than the
  // visible width, or a pixel format this code cannot write.  A false return
  // is a normal condition, never an error to report upward.
  //
  // The first form uses fb.base directly, which is correct only where the
  // framebuffer is identity mapped, as it is in physboot.  The second takes
  // the address the framebuffer is actually mapped at, for the kernel, where
  // fb.base remains the right thing to report but the wrong thing to store.
  bool Init(const zbi_swfb_t& fb);
  bool Init(const zbi_swfb_t& fb, void* mapped_base);

  // Reserves the top text row for a fixed banner, drawn in inverse video, and
  // moves the cursor below it.  Scrolling never reaches the reserved row, so
  // the banner stays legible for the whole boot.  This is what tells a reader
  // (and //validation:firstlight-uefi-boot, which measures it in pixels) which
  // stage owns the panel: a solid bar across the top row is the kernel's
  // console, while sparse text there is physboot's.
  void Banner(ktl::string_view text);

  bool active() const { return pixels_ != nullptr; }

  // Resulting text grid and magnification, for the startup announcement.
  uint32_t columns() const { return columns_; }
  uint32_t rows() const { return rows_; }
  uint32_t scale() const { return scale_; }

  // Renders `str` at the cursor, honouring '\n' and '\r' and discarding other
  // control characters.  Bytes outside printable ASCII draw as a filled block
  // so that unexpected output is visible rather than invisible.  Always claims
  // to have written everything: a console that cannot render a character must
  // not stall the caller.  This is the FILE::Write interface.
  int Write(ktl::string_view str);

  // The physical range that must stay mapped for Write() to work, for
  // AddressSpace::IdentityMapFramebuffer().  Empty when inactive.
  ktl::optional<uart::MmioRange> maybe_mmio_range() const;

  // Gives up the framebuffer, so Write() becomes a no-op instead of touching
  // memory it can no longer reach.  Used when the framebuffer cannot be mapped
  // into the address space about to be installed; going quiet is the only
  // acceptable outcome there, since faulting would take down a boot that would
  // otherwise have worked.
  void Disable();

 private:
  // Bytes per pixel is fixed at 4: both formats this supports are 32-bit.
  static constexpr uint32_t kBytesPerPixel = 4;

  void PutChar(char c);
  void Newline();
  void Scroll();
  void ClearRows(uint32_t y, uint32_t rows);
  void FillRows(uint32_t y, uint32_t rows, uint32_t color);

  volatile uint32_t* pixels_ = nullptr;  // Null means inactive.
  uint32_t width_ = 0;                   // Visible pixels per row.
  uint32_t height_ = 0;                  // Visible rows.
  uint32_t stride_ = 0;                  // Pixels per scanline, >= width_.
  uint32_t scale_ = 1;                   // Integer glyph magnification.
  uint32_t columns_ = 0, rows_ = 0;      // Text grid, in cells.
  uint32_t col_ = 0, row_ = 0;           // Cursor, in cells.
  uint32_t top_row_ = 0;                 // First row text may use; see Banner.
  uint32_t fg_ = 0, bg_ = 0;             // Pre-encoded pixel values.
};

// The single console instance.  Like GetUartDriver(), the reference returned
// is always the same, so it is safe to keep across calls.  physboot and the
// kernel are separate binaries and so have one of these each.
FramebufferConsole& GetFramebufferConsole();

// The kernel proper's entry points, defined in
// //zircon/kernel/lib/io/framebuffer-console.cc.  They are declared here, next
// to the renderer they drive, rather than in a kernel-only header, because
// this header is the one place that describes the console as a whole; the
// declarations cost physboot nothing.

struct PhysHandoff;

// Brings the console up on the framebuffer described by the hand-off, and
// draws its banner.  Called as the first thing in the kernel, before printf
// works, so that the panel shows the kernel is alive before anything that
// might hang.  A hand-off with no framebuffer leaves the console inactive and
// every other entry point a no-op.
void FramebufferConsoleInitEarly(const PhysHandoff& handoff);

// Draws `str`, or does nothing if there is no framebuffer console.  This is
// what //zircon/kernel/lib/io/console.cc feeds every kernel printf into.
void FramebufferConsoleWrite(ktl::string_view str);

// Reports the console on the kernel's ordinary log, once printf works.
void FramebufferConsoleAnnounce(const PhysHandoff& handoff);

#endif  // ZIRCON_KERNEL_PHYS_INCLUDE_PHYS_FRAMEBUFFER_CONSOLE_H_
