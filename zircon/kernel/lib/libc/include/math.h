// Copyright 2026 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_LIBC_INCLUDE_MATH_H_
#define ZIRCON_KERNEL_LIB_LIBC_INCLUDE_MATH_H_

#include <zircon/compiler.h>

// Minimal kernel math surface required by libc++ and existing kernel code.
// The kernel does not currently provide a full libm, but libc++ expects these
// classification macros to exist when it includes <cmath> / <math.h>.

#define FP_NAN 0
#define FP_INFINITE 1
#define FP_NORMAL 2
#define FP_SUBNORMAL 3
#define FP_ZERO 4

#define fpclassify(x) __builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL, \
                                           FP_ZERO, (x))
#define isnan(x) __builtin_isnan(x)
#define isinf(x) __builtin_isinf_sign(x)
#define isfinite(x) __builtin_isfinite(x)
#define signbit(x) __builtin_signbit(x)

#endif  // ZIRCON_KERNEL_LIB_LIBC_INCLUDE_MATH_H_
