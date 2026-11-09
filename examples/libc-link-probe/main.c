// Cerise probe: a DYNAMICALLY-LINKED Fuchsia binary that also calls into a
// CUSTOM shared library (libgreet.so). Reaching main + the cross-.so call proves the
// full runtime path: userboot -> ld.so.1 (loads libc.so + libgreet.so + vDSO,
// resolves cross-module symbols) -> C startup -> main. Markers via zx_debug_write
// (serial output; needs no handle, unlike zx_debuglog).
#include <zircon/syscalls.h>
#include <zircon/types.h>

#include "examples/libc-link-probe/greet.h"

int main(int argc, char** argv) {
  cerise_greet();  // cross-shared-library call into libgreet.so
  static const char kMsg[] = "CERISE-LIBC-DYN-OK\n";
  zx_debug_write(kMsg, sizeof(kMsg) - 1);
  return 0;
}
