// Copyright 2026 The Cerise Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include "lib/boot-shim/efi-gop.h"

#include <inttypes.h>

#include <efi/boot-services.h>
#include <efi/protocol/graphics-output.h>

namespace boot_shim {

zbi_pixel_format_t EfiGopItem::ZbiPixelFormat(const efi_graphics_output_mode_information& info) {
  switch (info.PixelFormat) {
    case PixelBlueGreenRedReserved8BitPerColor:
      // Little-endian BGRA bytes = 0xAARRGGBB words.  This is what OVMF and
      // most real x86 firmware (incl. Intel GOP) provide.
      return ZBI_PIXEL_FORMAT_ARGB_8888;
    case PixelRedGreenBlueReserved8BitPerColor:
      // Little-endian RGBA bytes = 0xAABBGGRR words.
      return ZBI_PIXEL_FORMAT_ABGR_8888;
    case PixelBitMask: {
      const efi_pixel_bitmask& m = info.PixelInformation;
      if (m.RedMask == 0x00ff0000 && m.GreenMask == 0x0000ff00 && m.BlueMask == 0x000000ff) {
        return ZBI_PIXEL_FORMAT_ARGB_8888;
      }
      if (m.RedMask == 0x000000ff && m.GreenMask == 0x0000ff00 && m.BlueMask == 0x00ff0000) {
        return ZBI_PIXEL_FORMAT_ABGR_8888;
      }
      if (m.RedMask == 0x0000f800 && m.GreenMask == 0x000007e0 && m.BlueMask == 0x0000001f) {
        return ZBI_PIXEL_FORMAT_RGB_565;
      }
      return ZBI_PIXEL_FORMAT_NONE;
    }
    case PixelBltOnly:  // No linear framebuffer to hand off.
    default:
      return ZBI_PIXEL_FORMAT_NONE;
  }
}

void EfiGopItem::Init(efi_system_table* systab, const char* shim_name, FILE* log) {
  if (systab == nullptr || systab->BootServices == nullptr) {
    return;
  }

  efi_graphics_output_protocol* gop = nullptr;
  efi_status status = systab->BootServices->LocateProtocol(
      &GraphicsOutputProtocol, nullptr, reinterpret_cast<void**>(&gop));
  if (status != EFI_SUCCESS || gop == nullptr || gop->Mode == nullptr ||
      gop->Mode->Info == nullptr) {
    // No GOP is a normal condition (e.g. headless): no item, no failure.
    fprintf(log, "%s: no UEFI GOP framebuffer; ZBI_TYPE_FRAMEBUFFER omitted\n", shim_name);
    return;
  }

  const efi_graphics_output_mode_information& info = *gop->Mode->Info;
  zbi_pixel_format_t format = ZbiPixelFormat(info);
  if (format == ZBI_PIXEL_FORMAT_NONE || gop->Mode->FrameBufferBase == 0) {
    fprintf(log, "%s: UEFI GOP pixel format %u not usable; ZBI_TYPE_FRAMEBUFFER omitted\n",
            shim_name, static_cast<unsigned>(info.PixelFormat));
    return;
  }

  set_payload(zbi_swfb_t{
      .base = gop->Mode->FrameBufferBase,
      .width = info.HorizontalResolution,
      .height = info.VerticalResolution,
      .stride = info.PixelsPerScanLine,
      .format = format,
  });

  // Serial marker consumed by //validation:firstlight-uefi-boot.
  fprintf(log, "%s: CERISE-SHIM-GOP-FB base=%#" PRIx64 " %" PRIu32 "x%" PRIu32 " stride=%" PRIu32
               " format=%#" PRIx32 "\n",
          shim_name, gop->Mode->FrameBufferBase, info.HorizontalResolution,
          info.VerticalResolution, info.PixelsPerScanLine, format);
}

}  // namespace boot_shim
