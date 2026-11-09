// Freestanding runtime support symbols libc.so references
// but the toolchain doesn't ship for x86_64-unknown-fuchsia. compiler-rt's
// builtins (muldc3/mulsc3/mulxc3) need __compilerrt_abort_impl; the libc bootstrap
// needs __stack_chk_* (a guard + a trap); libc++ headers' bounds checks call
// __libcpp_verbose_abort. All resolve to a trap (no recovery in the linker).
#include <stddef.h>
#include <stdint.h>

__attribute__((noreturn)) void __compilerrt_abort_impl(const char* file, int line,
                                                       const char* func) {
  __builtin_trap();
}

// Stack protector (libc is built -fno-stack-protector, but stray refs may remain).
uintptr_t __stack_chk_guard = 0x0;
__attribute__((noreturn)) void __stack_chk_fail(void) { __builtin_trap(); }

// libc++ contract-violation handler (called by hardened std:: bounds checks).
__attribute__((noreturn)) void _ZNSt3__122__libcpp_verbose_abortEPKcz(const char* fmt,
                                                                      ...) {
  __builtin_trap();
}

// Fuchsia has no settimeofday; the linux-compat musl shim was excluded. ENOSYS.
extern int __errno_location_value;
int settimeofday(const void* tv, const void* tz) { return -1; }

// The break-on-load debugger hook (ldso should_break_on_load -> debug_break).
// No-op without a debugger attached (break-on-load is off by default).
void debug_break(void) {}
