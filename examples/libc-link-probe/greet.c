// Dynamic-linking hardening: a CUSTOM shared library (not libc/vDSO). The probe calls
// cerise_greet() across the .so boundary — proving ld.so.1 loads an arbitrary
// DT_NEEDED shared object from bootfs, resolves the cross-module symbol, and applies
// its relocations. This is the "libc + a shared lib" part of the gate.
#include <zircon/syscalls.h>

__attribute__((visibility("default"))) void cerise_greet(void) {
  static const char kMsg[] = "CERISE-GREET-FROM-SO\n";
  zx_debug_write(kMsg, sizeof(kMsg) - 1);
}
