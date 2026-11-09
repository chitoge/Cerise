// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_LIB_UTF_CONVERSION_UTF_CONVERSION_H_
#define SRC_LIB_UTF_CONVERSION_UTF_CONVERSION_H_

#include <stddef.h>
#include <stdint.h>
#include <zircon/errors.h>
#include <zircon/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Convert a UTF-8 string to UTF-16.
//
// src:      source UTF-8 bytes (not necessarily null-terminated)
// src_len:  number of bytes in src
// dst:      destination buffer for UTF-16 code units (may be NULL for dry-run)
// dst_len:  in: capacity of dst in uint16_t units (ignored if dst is NULL)
//           out: number of uint16_t units written (not including any null terminator)
//
// Returns ZX_OK on success, ZX_ERR_INVALID_ARGS on malformed UTF-8,
// ZX_ERR_BUFFER_TOO_SMALL if dst is non-NULL but not large enough.
zx_status_t utf8_to_utf16(const uint8_t* src, size_t src_len, uint16_t* dst, size_t* dst_len);

// Convert a UTF-16 string to UTF-8.
//
// src:      source UTF-16 code units (not necessarily null-terminated)
// src_len:  number of uint16_t code units in src
// dst:      destination buffer for UTF-8 bytes (may be NULL for dry-run)
// dst_len:  in: capacity of dst in bytes (ignored if dst is NULL)
//           out: number of bytes written (not including any null terminator)
//
// Returns ZX_OK on success, ZX_ERR_INVALID_ARGS on malformed UTF-16,
// ZX_ERR_BUFFER_TOO_SMALL if dst is non-NULL but not large enough.
zx_status_t utf16_to_utf8(const uint16_t* src, size_t src_len, uint8_t* dst, size_t* dst_len);

#ifdef __cplusplus
}
#endif

#endif  // SRC_LIB_UTF_CONVERSION_UTF_CONVERSION_H_
