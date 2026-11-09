// Passthrough no-op "clang-format": ignore all args (e.g. --style=google) and
// copy stdin to stdout unchanged. configc invokes the formatter as a
// stdin->stdout filter purely to pretty-print generated source; an identity
// filter yields valid (un-pretty-printed) source that compiles identically.
// Used until a real clang-format is wired (the minimal LLVM toolchain stubs
// clang-format to an `empty` symlink). Cosmetic-only; revisit.
#include <unistd.h>

int main(void) {
  char buf[8192];
  ssize_t n;
  while ((n = read(0, buf, sizeof buf)) > 0) {
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = write(1, buf + off, (size_t)(n - off));
      if (w < 0) return 1;
      off += w;
    }
  }
  return n < 0 ? 1 : 0;
}
