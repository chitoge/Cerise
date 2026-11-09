// Copyright 2026 The Cerise Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <phys/framebuffer-console-zbi.h>

#include <inttypes.h>
#include <lib/zbi-format/graphics.h>
#include <lib/zbi-format/zbi.h>
#include <string.h>

#include <ktl/optional.h>
#include <ktl/span.h>
#include <phys/stdio.h>

#include <ktl/enforce.h>

void SetFramebufferConsole(EarlyBootZbi& zbi) {
  ktl::optional<zbi_swfb_t> fb;
  for (auto [header, wrapped_payload] : zbi) {
    if (header->type == ZBI_TYPE_FRAMEBUFFER) {
      ktl::span payload = wrapped_payload.get();
      if (payload.size() >= sizeof(zbi_swfb_t)) {
        // The payload is not guaranteed to be aligned for zbi_swfb_t, so copy
        // rather than reinterpret it.  Later items win, matching how the ZBI
        // treats repeated configuration generally.
        zbi_swfb_t item;
        memcpy(&item, payload.data(), sizeof(item));
        fb = item;
      }
    }
  }
  zbi.ignore_error();

  if (!fb) {
    // No framebuffer item is the normal case on every serial-only boot.
    return;
  }

  FramebufferConsole& console = GetFramebufferConsole();
  if (!console.Init(*fb)) {
    return;
  }
  PhysConsole::Get().set_graphics(FILE{&console});

  // Announce on the way out, deliberately AFTER set_graphics so this line is
  // itself drawn on the framebuffer.  That makes it evidence rather than a
  // claim: seeing it on the panel proves the blitter works, and seeing it on
  // serial proves the item was parsed.  //validation:firstlight-uefi-boot
  // asserts both.  printf (not debugf) because a console that only announces
  // itself under kernel.phys.verbose is useless for diagnosing a silent boot.
  printf("phys: CERISE-PHYS-FB-CONSOLE base=%#" PRIx64 " %" PRIu32 "x%" PRIu32 " stride=%" PRIu32
         " format=%#" PRIx32 " %" PRIu32 "x%" PRIu32 " cells scale=%" PRIu32 "\n",
         fb->base, fb->width, fb->height, fb->stride, fb->format, console.columns(), console.rows(),
         console.scale());
}
