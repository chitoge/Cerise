/* Compile a trivial .c probe against the vendored musl public headers
 * for the x86_64-unknown-fuchsia target. A green build proves the musl header
 * surface + the minimal fuchsia cc toolchain compile C for the Fuchsia target
 * (compile-only — linking against libc.so/ld.so.1/d). */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

uint32_t libc_probe_len(const char *s) {
  return (uint32_t)strlen(s);
}

int libc_probe_eq(const char *a, const char *b, size_t n) {
  return memcmp(a, b, n) == 0;
}
