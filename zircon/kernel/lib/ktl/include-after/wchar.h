// Copyright 2018 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_KTL_INCLUDE_AFTER_WCHAR_H_
#define ZIRCON_KERNEL_LIB_KTL_INCLUDE_AFTER_WCHAR_H_

#include <stddef.h>

// The kernel doesn't want this file but some libc++ headers we need wind up
// including it and they need these declarations.
//
// **NOTE** This file is include-after because libc++ headers get it via
// #include_next so as to get the "system" <wchar.h> rather than libc++'s
// own wrapper.

#ifndef ____mbstate_t_defined
#define ____mbstate_t_defined 1

#ifndef __WINT_TYPE__
#define __WINT_TYPE__ unsigned int
#endif

typedef struct {
	int __count;
	union {
		__WINT_TYPE__ __wch;
		char __wchb[4];
	} __value;
} __mbstate_t;

#endif

#ifndef __mbstate_t_defined
#define __mbstate_t_defined 1
typedef __mbstate_t mbstate_t;
#endif

#ifndef __wint_t_defined
#define __wint_t_defined 1

#ifndef _WINT_T
#define _WINT_T 1
typedef __WINT_TYPE__ wint_t;
#endif

#endif

#ifndef WEOF
#define WEOF (~wint_t{0})
#endif

// <string_view> refers to these in code that's never actually used in ktl.
wchar_t* wmemcpy(wchar_t* __restrict, const wchar_t* __restrict, size_t);
wchar_t* wmemmove(wchar_t*, const wchar_t*, size_t);
wchar_t* wmemset(wchar_t*, wchar_t, size_t);

#endif  // ZIRCON_KERNEL_LIB_KTL_INCLUDE_AFTER_WCHAR_H_
