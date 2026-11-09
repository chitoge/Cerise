// Temporary elfldltl compatibility shim for the curated workspace snapshot.
// This only preserves the narrow Elf::Addr surface currently needed by
// zircon/kernel/phys/include/phys/handoff.h while the real elfldltl headers
// are absent.

#ifndef TOOLS_FIDL_INCLUDE_LIB_ELFLDLTL_LAYOUT_H_
#define TOOLS_FIDL_INCLUDE_LIB_ELFLDLTL_LAYOUT_H_

#include <stdint.h>

namespace elfldltl {

template <typename = void>
struct Elf {
  using Addr = uintptr_t;
};

}  // namespace elfldltl

#endif  // TOOLS_FIDL_INCLUDE_LIB_ELFLDLTL_LAYOUT_H_