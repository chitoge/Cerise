// Cerise posix_probe: prove that a PLAIN C component — linking only
// the default sysroot (libc + libzircon + the shared libfdio.so; NO static
// fdio) — gets working POSIX file I/O and stdio out of the box.
//
// What this exercises, in order:
//   1. load-time: DT_NEEDED libfdio.so binds the REAL shared fdio; musl libc's
//      weak ENOSYS fallbacks (open/read/write/writev/...) lose to its strong
//      definitions, and libc startup calls libfdio.so's __libc_extensions_init
//      with the processargs handles (PA_NS_DIR namespace + elf_runner's
//      PA_FD(1)/(2) LogSink-bound sockets).
//   2. open()/read()/close() of /pkg/data/probe.txt — the component's own
//      package directory, served from bootfs through the fdio namespace.
//      Success is reported directly to serial via zx_debug_write (the belt:
//      it does not depend on any stdout wiring).
//   3. printf() — musl stdio -> writev(1) -> libfdio.so -> the fd1 zx socket
//      elf_runner installed -> drained into fuchsia.logger.LogSink (the
//      Archivist). archivist_reader queries the record back over
//      ArchiveAccessor and emits CERISE-POSIX-PROBE-OK on serial; that marker
//      is this probe's printf acceptance.
//
// Markers (asserted by //validation:posix-probe-boot):
//   CERISE-POSIX-PROBE-START        probe entered main
//   CERISE-POSIX-PROBE-IO-OK        open/read/close + content check passed
//   CERISE-POSIX-PROBE-PRINTF-SENT  printf/fflush returned success
//   CERISE-POSIX-PROBE-FAIL <why>   any step failed (fails the gate)
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zircon/syscalls.h>

// The needle the staged /pkg/data/probe.txt must contain.
#define FILE_NEEDLE "cerise-posix-file-needle-9c51"
// The needle archivist_reader greps out of the ingested stdout record.
#define PRINTF_NEEDLE "cerise-posix-printf-needle-42a7"

static void dbg(const char* s) { zx_debug_write(s, strlen(s)); }

static void fail(const char* why) {
  dbg("CERISE-POSIX-PROBE-FAIL ");
  dbg(why);
  dbg("\n");
}

int main(void) {
  dbg("CERISE-POSIX-PROBE-START\n");

  // fd1 is a zx socket (not a tty): musl stdio would fully buffer it. Make
  // printf write through immediately so the record reaches the Archivist even
  // though this process exits right after.
  setvbuf(stdout, NULL, _IONBF, 0);

  // (2) POSIX file I/O through the loaded libfdio.so.
  int fd = open("/pkg/data/probe.txt", O_RDONLY);
  if (fd < 0) {
    fail(errno == ENOSYS ? "open-enosys-stub-fdio" : "open");
    return 1;
  }
  char buf[128] = {0};
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  if (n <= 0) {
    fail("read");
    return 1;
  }
  if (close(fd) != 0) {
    fail("close");
    return 1;
  }
  if (strstr(buf, FILE_NEEDLE) == NULL) {
    fail("content");
    return 1;
  }
  dbg("CERISE-POSIX-PROBE-IO-OK\n");

  // (3) stdio: printf to fd1. With the old ENOSYS stub this SILENTLY failed
  // (writev -> -ENOSYS surfaced only as the stream's F_ERR flag) — exactly the
  // debugging trap in which a read error looks like EOF; ferror() catches it.
  int rc = printf("CERISE-POSIX-PROBE-PRINTF %s\n", PRINTF_NEEDLE);
  if (rc < 0 || ferror(stdout) || fflush(stdout) != 0) {
    fail("printf");
    return 1;
  }
  dbg("CERISE-POSIX-PROBE-PRINTF-SENT\n");
  return 0;
}
