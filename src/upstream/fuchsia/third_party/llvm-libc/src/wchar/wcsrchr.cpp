//===-- Implementation of wcsrchr -----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/wchar/wcsrchr.h"

#include "hdr/types/wchar_t.h"
#include "src/__support/common.h"
#include "src/__support/macros/config.h"

namespace LIBC_NAMESPACE_DECL {

LLVM_LIBC_FUNCTION(const wchar_t *, wcsrchr, (const wchar_t *s, wchar_t c)) {
  const wchar_t *last = nullptr;
  for (; *s; ++s) {
    if (*s == c)
      last = s;
  }
  if (c == L'\0')
    return s;
  return last;
}

} // namespace LIBC_NAMESPACE_DECL
