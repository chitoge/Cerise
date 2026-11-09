// Kernel stubs: hw_watchdog, code-patching self-test, x86 user-copy, and libc runtime globals.
// (VDso stubs removed — real vdso.cc is now compiled via userabi target.)
#include <dev/hw_watchdog.h>
#include <lib/code-patching/self-test.h>
#include <zircon/errors.h>
#include <new>
#include <stddef.h>
#include <stdint.h>

// Hardware watchdog: no-op until a platform watchdog driver is registered.
extern "C" void hw_watchdog_pet(void) {}
extern "C" void hw_watchdog_suppress_petting(bool suppress) { (void)suppress; }
extern "C" zx_status_t hw_watchdog_set_enabled(bool enabled) {
  (void)enabled;
  return ZX_OK;
}

// Canonical ELF DSO handle (self-pointer is the standard definition).
extern "C" { void* __dso_handle = &__dso_handle; }

// Code-patching self-test: no-op until the code-patching engine (lib/code-patching) is wired.
// Wiring self-test.S without the engine would fire assert.fail on every boot.
extern "C" void CodePatchingNopTest() {}

// _x86_copy_to_or_from_user is NOT defined here.  It used to be a C shim that
// unconditionally forwarded to _x86_copy_to_or_from_user_movsq -- the variant
// built *without* -DSMAP, i.e. without the stac/clac bracketing the copy.  On
// any SMAP-capable CPU (Broadwell and later) that made every user copy a
// supervisor access to a user page with EFLAGS.AC clear, which faults; it was
// invisible only because QEMU's default CPU model does not advertise SMAP.
// The symbol is now the code-patching stub in
// //zircon/kernel/arch/x86/user-copy:user_copy_stub, whose body physboot
// replaces at boot with the alternative chosen by
// SelectX86UserCopyAlternative() (SMAP- and ERMS-aware).

// Retpoline for r11: prevents speculative indirect jumps (Spectre V2 mitigation).
// Equivalent to __x86_indirect_thunk_basic_r11 in retpoline/basic.S.
// When code-patching is wired, SelectX86RetpolineAlternative() will choose between
// basic (default) and unsafe (x86_disable_spec_mitigations boot flag) at runtime.
extern "C" __attribute__((naked)) void __x86_indirect_thunk_r11() {
  __asm__(
    "call 1f\n\t"
    "0:\n\t"
    "  pause\n\t"
    "  lfence\n\t"
    "  jmp 0b\n\t"
    "1:\n\t"
    "  movq %r11, (%rsp)\n\t"
    "  ret\n\t"
    "  int3"
  );
}

// Kernel nothrow new: returns nullptr (correct — the kernel has no heap for nothrow callers).
// Matches stub-new.cc in //zircon/kernel/lib/ktl (not compiled via cc_library chain here).
namespace std { const nothrow_t nothrow{}; }
void* operator new(size_t, const std::nothrow_t&) noexcept { return nullptr; }
void* operator new[](size_t, const std::nothrow_t&) noexcept { return nullptr; }
