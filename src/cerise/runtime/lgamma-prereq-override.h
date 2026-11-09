// force-included (-include) into every libcxx/libcxxabi TU we build
// for Fuchsia. Our musl/llvm-libc hybrid headers declare lgamma_r (and the
// rest of <math.h>) __NOEXCEPT=noexcept, but on non-Linux targets libcxx's
// __configuration/platform.h defines _LIBCPP_GLIBC_PREREQ(a, b) as 0
// unconditionally, so __random/binomial_distribution.h takes its
// defined(_LIBCPP_GLIBC_PREREQ) branch and redeclares lgamma_r WITHOUT
// noexcept (its defined(__LLVM_LIBC__) elif is unreachable dead code) — a
// hard compile error that historically forced <random> out of libc++.
//
// Override: include platform.h first (its include guard then makes the later
// include from __config a no-op) and redefine the probe to answer true
// exactly for (2, 8) — "libc declares lgamma_r noexcept", which is true for
// our libc. Every other current use ((2, 30) pthread_cond_clockwait, (2, 36)
// c8rtomb) keeps evaluating to 0, exactly as before.
#ifndef CERISE_RUNTIME_LGAMMA_PREREQ_OVERRIDE_H_
#define CERISE_RUNTIME_LGAMMA_PREREQ_OVERRIDE_H_

#ifdef __cplusplus
#include <__configuration/platform.h>
#undef _LIBCPP_GLIBC_PREREQ
#define _LIBCPP_GLIBC_PREREQ(a, b) ((a) == 2 && (b) == 8)
#endif  // __cplusplus

#endif  // CERISE_RUNTIME_LGAMMA_PREREQ_OVERRIDE_H_
