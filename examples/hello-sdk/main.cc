// Minimal example demonstrating build against the //sdk surface.
// Includes only headers exposed via //sdk:zircon_api.
#include "lib/syscalls/zx-syscall-numbers.h"

// Compile-time assertion: the SDK-derived syscall table is non-empty.
static_assert(ZX_SYS_COUNT > 0, "SDK zircon_api must expose at least one syscall");
