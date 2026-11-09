// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIB_C_SCUDO_SCUDO_PLATFORM_TLS_SLOT_H_
#define LIB_C_SCUDO_SCUDO_PLATFORM_TLS_SLOT_H_

#include <stdint.h>

// SCUDO_HAS_PLATFORM_TLS_SLOT tells the Scudo sources to include this file and call this
// function instead of using a `thread_local` of its own. The slot lives in musl's struct
// pthread (->scudo_tsd).
//
// CERISE: upstream defines this inline as `&__pthread_self()->scudo_tsd`, which makes
// every scudo C++ TU #include threads_impl.h. In Cerise's toolchain that pulls the deep
// musl-internal C header closure ahead of libc++, breaking libc++ header ordering (and
// dragging in the C++-only <lib/zx/thread.h>). So the accessor is defined out-of-line in
// scudo_tls_slot.c (compiled as C in the musl-internal environment) and declared here.
//
// TODO(https://fxbug.dev/42142757): once a standalone dynamic linker lets libc have its
// own `thread_local`, this platform-slot mechanism can go away.
#ifdef __cplusplus
extern "C" {
#endif
uintptr_t *getPlatformAllocatorTlsSlot(void);
#ifdef __cplusplus
}
#endif

#endif  // LIB_C_SCUDO_SCUDO_PLATFORM_TLS_SLOT_H_
