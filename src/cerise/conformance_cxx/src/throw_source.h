// Cerise conformance_cxx: the cross-.so throw surface. This header is
// shared between libconfthrow.so (which THROWS) and the main probe binary (which
// CATCHES). The acid test for the C++ runtime is that an exception thrown inside
// the shared object unwinds across the DT_NEEDED boundary and is caught in the
// main executable — which requires the unwinder to enumerate the .so's eh_frame
// via dl_iterate_phdr at runtime.
#ifndef CERISE_CONFORMANCE_CXX_THROW_SOURCE_H_
#define CERISE_CONFORMANCE_CXX_THROW_SOURCE_H_

#include <stdexcept>

namespace cerise::conf {

// A derived exception type. It is thrown in the .so and caught BY BASE
// (std::exception / std::runtime_error) in the main binary: the base typeinfo
// lives once in the shared libc++.so.1, so catch-by-base matches across the
// boundary regardless of where the derived type's weak typeinfo was emitted.
struct ConfThrowError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

// Defined in throw_source.cc, compiled into libconfthrow.so, exported with
// default visibility (no version script) so the main binary's DT_NEEDED link
// resolves it. Throws ConfThrowError from `depth` nested frames deep so the
// unwinder must walk real DWARF CFI inside the .so before crossing back to main.
__attribute__((visibility("default"))) void ThrowFromSo(int depth);

}  // namespace cerise::conf

#endif  // CERISE_CONFORMANCE_CXX_THROW_SOURCE_H_
