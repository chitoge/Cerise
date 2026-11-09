#include "lib/syscalls/zx-syscall-numbers.h"

static_assert(ZX_SYS_COUNT > 0);

int main() {
  return kSyscallNames[0] == nullptr;
}