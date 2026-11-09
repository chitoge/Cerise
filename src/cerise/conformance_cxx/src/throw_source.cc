// Cerise conformance_cxx: the THROW side of the cross-.so exception
// test. Compiled into libconfthrow.so (a real shared object staged in the
// probe's package lib/). ThrowFromSo throws from `depth` nested, noinline frames
// so the throw crosses real call frames inside the .so and the unwinder must walk
// DWARF CFI here before unwinding back across the DT_NEEDED boundary into the main
// binary, which catches by base. If this path fails at runtime the root cause is
// almost certainly that dl_iterate_phdr does not enumerate this .so's FDEs.
#include "throw_source.h"

namespace cerise::conf {

[[gnu::noinline]] static void ThrowDeep(int depth) {
  if (depth <= 0) {
    throw ConfThrowError("thrown-in-libconfthrow.so");
  }
  ThrowDeep(depth - 1);
  // Keep the frame non-trivial so it is not folded away.
  asm volatile("" ::: "memory");
}

void ThrowFromSo(int depth) { ThrowDeep(depth); }

}  // namespace cerise::conf
