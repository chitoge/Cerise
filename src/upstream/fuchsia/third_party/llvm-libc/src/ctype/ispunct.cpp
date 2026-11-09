//===-- Implementation of ispunct------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/ctype/ispunct.h"

#include "src/__support/CPP/limits.h"
#include "src/__support/common.h"
#include "src/__support/ctype_utils.h"
#include "src/__support/macros/config.h"

namespace LIBC_NAMESPACE_DECL {

// ispunct: printable and not space and not alnum
LLVM_LIBC_FUNCTION(int, ispunct, (int c)) {
  if (c < 0 || c > cpp::numeric_limits<unsigned char>::max())
    return 0;
  unsigned char uc = static_cast<unsigned char>(c);
  return static_cast<int>(
      (uc - 0x20u) < 0x5fu && uc != ' ' && !internal::isalnum(static_cast<char>(uc)));
}

} // namespace LIBC_NAMESPACE_DECL
