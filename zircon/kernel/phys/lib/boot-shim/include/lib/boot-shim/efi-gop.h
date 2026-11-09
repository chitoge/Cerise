// Copyright 2026 The Cerise Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_PHYS_LIB_BOOT_SHIM_INCLUDE_LIB_BOOT_SHIM_EFI_GOP_H_
#define ZIRCON_KERNEL_PHYS_LIB_BOOT_SHIM_INCLUDE_LIB_BOOT_SHIM_EFI_GOP_H_

#include <lib/zbi-format/graphics.h>
#include <stdio.h>

#include <efi/protocol/graphics-output.h>
#include <efi/system-table.h>

#include "item-base.h"

namespace boot_shim {

// Queries the UEFI Graphics Output Protocol (before ExitBootServices) and, if
// a linear framebuffer is available, supplies a ZBI_TYPE_FRAMEBUFFER item
// (zbi_swfb_t) describing it.  GOP absent, Blt-only, or an unmappable pixel
// format all simply produce no item — never a failure.  Same shape as
// upstream gigaboot's framebuffer item.
class EfiGopItem : public SingleOptionalItem<zbi_swfb_t, ZBI_TYPE_FRAMEBUFFER> {
 public:
  // Matches EfiBootShim<...>::Init's SFINAE dispatch signature, so this runs
  // automatically for shims that include this item.
  void Init(efi_system_table* systab, const char* shim_name, FILE* log);

  // Maps a GOP mode's pixel format to a ZBI_PIXEL_FORMAT_* value, or
  // ZBI_PIXEL_FORMAT_NONE if it has no linear-framebuffer ZBI equivalent.
  // Exposed for unit testing.
  static zbi_pixel_format_t ZbiPixelFormat(const efi_graphics_output_mode_information& info);
};

}  // namespace boot_shim

#endif  // ZIRCON_KERNEL_PHYS_LIB_BOOT_SHIM_INCLUDE_LIB_BOOT_SHIM_EFI_GOP_H_
