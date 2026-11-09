//===-- Implementation of wmemmove ----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/wchar/wmemmove.h"

#include "hdr/types/size_t.h"
#include "hdr/types/wchar_t.h"
#include "src/__support/common.h"
#include "src/__support/macros/config.h"

namespace LIBC_NAMESPACE_DECL {

LLVM_LIBC_FUNCTION(wchar_t *, wmemmove,
                   (wchar_t *dest, const wchar_t *src, size_t n)) {
  if (dest <= src || dest >= src + n) {
    for (size_t i = 0; i < n; ++i)
      dest[i] = src[i];
  } else {
    for (size_t i = n; i > 0; --i)
      dest[i - 1] = src[i - 1];
  }
  return dest;
}

} // namespace LIBC_NAMESPACE_DECL
