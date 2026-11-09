//===-- Implementation of isxdigit-----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/ctype/isxdigit.h"

#include "src/__support/CPP/limits.h"
#include "src/__support/common.h"
#include "src/__support/macros/config.h"

namespace LIBC_NAMESPACE_DECL {

LLVM_LIBC_FUNCTION(int, isxdigit, (int c)) {
  if (c < 0 || c > cpp::numeric_limits<unsigned char>::max())
    return 0;
  unsigned char uc = static_cast<unsigned char>(c);
  return (uc >= '0' && uc <= '9') || (uc >= 'a' && uc <= 'f') ||
         (uc >= 'A' && uc <= 'F');
}

} // namespace LIBC_NAMESPACE_DECL
