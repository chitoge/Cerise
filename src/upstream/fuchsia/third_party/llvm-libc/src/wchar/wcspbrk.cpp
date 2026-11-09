//===-- Implementation of wcspbrk -----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/wchar/wcspbrk.h"

#include "hdr/types/wchar_t.h"
#include "src/__support/common.h"
#include "src/__support/macros/config.h"

namespace LIBC_NAMESPACE_DECL {

LLVM_LIBC_FUNCTION(const wchar_t *, wcspbrk,
                   (const wchar_t *src, const wchar_t *breakset)) {
  for (; *src; ++src) {
    for (const wchar_t *b = breakset; *b; ++b) {
      if (*src == *b)
        return src;
    }
  }
  return nullptr;
}

} // namespace LIBC_NAMESPACE_DECL
