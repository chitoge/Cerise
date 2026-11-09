// Copyright 2026 The Cerise Authors. Cerise sysroot-provided header.
//
// <zircon/status.h> is part of Fuchsia's zircon public/sysroot surface but is
// absent from the vendored zircon/system/public subtree at the pinned commit
// (it is delivered via the generated sysroot upstream). This is a faithful
// reproduction of that small, stable public API header, provided here so the
// libc sources that use zx_status_get_string (e.g. src/mman/*) compile for the
// fuchsia target. Replace with the vendored/generated original if/when wired.

#ifndef CERISE_SYSROOT_ZIRCON_STATUS_H_
#define CERISE_SYSROOT_ZIRCON_STATUS_H_

#include <zircon/compiler.h>
#include <zircon/types.h>

__BEGIN_CDECLS

// Returns a string constant describing |status|, or "(UNKNOWN)" if unknown.
const char* _zx_status_get_string(zx_status_t status);
const char* zx_status_get_string(zx_status_t status);

__END_CDECLS

#endif  // CERISE_SYSROOT_ZIRCON_STATUS_H_
