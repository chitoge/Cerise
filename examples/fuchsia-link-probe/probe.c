/* A minimal freestanding probe that LINKS against the libzircon.so
 * sysroot stub for x86_64-unknown-fuchsia. Proves the fuchsia toolchain can now
 * resolve zx_* symbols at link time (the foundation anchor works). It is not run
 * (no crt/loader yet) — this is a link-only validation. */

/* Declared by <zircon/syscalls.h>; provided by libzircon.so (the vDSO at runtime). */
void _zx_process_exit(long retcode);

void _start(void) {
  _zx_process_exit(0);
}
