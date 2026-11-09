// Temporary elfldltl compatibility shim for the curated workspace snapshot.
// This only preserves the narrow InitFiniInfo surface currently used by
// zircon/kernel/top/main.cc while the real elfldltl headers are absent.

#ifndef TOOLS_FIDL_INCLUDE_LIB_ELFLDLTL_INIT_FINI_H_
#define TOOLS_FIDL_INCLUDE_LIB_ELFLDLTL_INIT_FINI_H_

#include <span>

namespace elfldltl {

template <typename = void>
class InitFiniInfo {
 public:
  constexpr InitFiniInfo() = default;

  template <typename T, std::size_t Extent>
  constexpr explicit InitFiniInfo(std::span<const T, Extent>) {}

  constexpr void CallInit() const {}
};

}  // namespace elfldltl

#endif  // TOOLS_FIDL_INCLUDE_LIB_ELFLDLTL_INIT_FINI_H_