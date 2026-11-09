#ifndef TOOLS_FIDL_INCLUDE_LIB_ELFLDLTL_MACHINE_H_
#define TOOLS_FIDL_INCLUDE_LIB_ELFLDLTL_MACHINE_H_

#include <stdint.h>

namespace elfldltl {

enum class ElfMachine {
  kNone,
  kX86_64,
  kNative = kX86_64,
};

template <ElfMachine Machine = ElfMachine::kNative>
struct AbiTraits;

template <>
struct AbiTraits<ElfMachine::kNone> {
  template <typename SizeType = uintptr_t>
  static constexpr SizeType kStackAlignment = 16;

  template <typename SizeType>
  static constexpr SizeType InitialStackPointer(SizeType base, SizeType size) {
    return (base + size) & -kStackAlignment<SizeType>;
  }
};

template <>
struct AbiTraits<ElfMachine::kX86_64> : public AbiTraits<ElfMachine::kNone> {
  template <typename SizeType>
  static constexpr SizeType InitialStackPointer(SizeType base, SizeType size) {
    return AbiTraits<ElfMachine::kNone>::InitialStackPointer(base, size) - 8;
  }
};

}  // namespace elfldltl

#endif  // TOOLS_FIDL_INCLUDE_LIB_ELFLDLTL_MACHINE_H_