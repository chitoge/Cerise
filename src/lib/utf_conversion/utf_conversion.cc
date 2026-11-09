// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "utf_conversion.h"

#include <stddef.h>
#include <stdint.h>
#include <zircon/errors.h>

// UTF-8 to UTF-16 conversion.
//
// Encodes each Unicode codepoint from the UTF-8 source into one or two
// UTF-16 code units (surrogate pairs for codepoints > U+FFFF).
zx_status_t utf8_to_utf16(const uint8_t* src, size_t src_len, uint16_t* dst, size_t* dst_len) {
  size_t out = 0;
  size_t capacity = (dst != nullptr) ? *dst_len : SIZE_MAX;

  for (size_t i = 0; i < src_len;) {
    uint32_t cp;
    uint8_t b = src[i];
    size_t bytes;

    if ((b & 0x80) == 0) {
      cp = b;
      bytes = 1;
    } else if ((b & 0xE0) == 0xC0) {
      cp = b & 0x1F;
      bytes = 2;
    } else if ((b & 0xF0) == 0xE0) {
      cp = b & 0x0F;
      bytes = 3;
    } else if ((b & 0xF8) == 0xF0) {
      cp = b & 0x07;
      bytes = 4;
    } else {
      return ZX_ERR_INVALID_ARGS;
    }

    if (i + bytes > src_len) {
      return ZX_ERR_INVALID_ARGS;
    }
    for (size_t j = 1; j < bytes; j++) {
      if ((src[i + j] & 0xC0) != 0x80) {
        return ZX_ERR_INVALID_ARGS;
      }
      cp = (cp << 6) | (src[i + j] & 0x3F);
    }
    i += bytes;

    // Encode codepoint as UTF-16.
    if (cp < 0x10000) {
      if (dst != nullptr) {
        if (out >= capacity) {
          return ZX_ERR_BUFFER_TOO_SMALL;
        }
        dst[out] = static_cast<uint16_t>(cp);
      }
      out++;
    } else {
      cp -= 0x10000;
      if (dst != nullptr) {
        if (out + 2 > capacity) {
          return ZX_ERR_BUFFER_TOO_SMALL;
        }
        dst[out] = static_cast<uint16_t>(0xD800 | (cp >> 10));
        dst[out + 1] = static_cast<uint16_t>(0xDC00 | (cp & 0x3FF));
      }
      out += 2;
    }
  }

  *dst_len = out;
  return ZX_OK;
}

// UTF-16 to UTF-8 conversion.
//
// Decodes each UTF-16 code unit (including surrogate pairs) into a Unicode
// codepoint and encodes it as UTF-8.
zx_status_t utf16_to_utf8(const uint16_t* src, size_t src_len, uint8_t* dst, size_t* dst_len) {
  size_t out = 0;
  size_t capacity = (dst != nullptr) ? *dst_len : SIZE_MAX;

  for (size_t i = 0; i < src_len;) {
    uint32_t cp;
    uint16_t u = src[i++];

    if (u >= 0xD800 && u <= 0xDBFF) {
      // High surrogate — expect a low surrogate next.
      if (i >= src_len) {
        return ZX_ERR_INVALID_ARGS;
      }
      uint16_t lo = src[i++];
      if (lo < 0xDC00 || lo > 0xDFFF) {
        return ZX_ERR_INVALID_ARGS;
      }
      cp = 0x10000 + (static_cast<uint32_t>(u - 0xD800) << 10) + (lo - 0xDC00);
    } else if (u >= 0xDC00 && u <= 0xDFFF) {
      return ZX_ERR_INVALID_ARGS;  // Lone low surrogate.
    } else {
      cp = u;
    }

    // Encode codepoint as UTF-8.
    uint8_t encoded[4];
    size_t encoded_len;
    if (cp < 0x80) {
      encoded[0] = static_cast<uint8_t>(cp);
      encoded_len = 1;
    } else if (cp < 0x800) {
      encoded[0] = static_cast<uint8_t>(0xC0 | (cp >> 6));
      encoded[1] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
      encoded_len = 2;
    } else if (cp < 0x10000) {
      encoded[0] = static_cast<uint8_t>(0xE0 | (cp >> 12));
      encoded[1] = static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F));
      encoded[2] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
      encoded_len = 3;
    } else {
      encoded[0] = static_cast<uint8_t>(0xF0 | (cp >> 18));
      encoded[1] = static_cast<uint8_t>(0x80 | ((cp >> 12) & 0x3F));
      encoded[2] = static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F));
      encoded[3] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
      encoded_len = 4;
    }

    if (dst != nullptr) {
      if (out + encoded_len > capacity) {
        return ZX_ERR_BUFFER_TOO_SMALL;
      }
      for (size_t j = 0; j < encoded_len; j++) {
        dst[out + j] = encoded[j];
      }
    }
    out += encoded_len;
  }

  *dst_len = out;
  return ZX_OK;
}
