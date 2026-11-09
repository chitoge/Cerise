//===-- Implementation of wcscspn -----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/wchar/wcscspn.h"

#include "hdr/types/size_t.h"
#include "hdr/types/wchar_t.h"
#include "src/__support/common.h"
#include "src/__support/macros/config.h"

namespace LIBC_NAMESPACE_DECL {

LLVM_LIBC_FUNCTION(size_t, wcscspn,
                   (const wchar_t *s1, const wchar_t *s2)) {
  const wchar_t *p = s1;
  while (*p) {
    for (const wchar_t *q = s2; *q; ++q) {
      if (*p == *q)
        return static_cast<size_t>(p - s1);
    }
    ++p;
  }
  return static_cast<size_t>(p - s1);
}

} // namespace LIBC_NAMESPACE_DECL
