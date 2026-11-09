// Cerise: out-of-line accessor for scudo's per-thread TSD slot, which lives in musl's
// struct pthread (->scudo_tsd). Compiled as C in the musl-internal environment so scudo's
// C++ translation units don't have to #include threads_impl.h. Pulling the deep
// musl-internal header closure into a C++ compile shadows libc++'s header ordering (and
// drags in the C++-only <lib/zx/thread.h>); keeping the slot accessor in a separate C TU
// avoids that entirely. scudo_platform_tls_slot.h declares this extern "C".
#include <stdint.h>

#include "threads_impl.h"

uintptr_t *getPlatformAllocatorTlsSlot(void) { return &__pthread_self()->scudo_tsd; }
