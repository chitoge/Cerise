// Copyright 2025 The Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// Phys-environment override for <zircon/assert.h>.
// In phys builds, _KERNEL is defined by the toolchain, but phys code still
// needs __zx_panic declared (it's defined in phys/panic.cc).  Temporarily
// undefine _KERNEL so the non-kernel path of zircon/assert.h is used.

#ifndef PHYS_BUILD_INCLUDE_ZIRCON_ASSERT_H_
#define PHYS_BUILD_INCLUDE_ZIRCON_ASSERT_H_

#ifdef _KERNEL
#undef _KERNEL
#include_next <zircon/assert.h>
#define _KERNEL 1
#else
#include_next <zircon/assert.h>
#endif

#endif  // PHYS_BUILD_INCLUDE_ZIRCON_ASSERT_H_
