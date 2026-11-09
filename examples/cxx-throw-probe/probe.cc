// C++ exceptions link-readiness probe (and the seed for the #34
// runtime-conformance boot gate). Built for the Fuchsia target with
// -fexceptions; LINK success proves __cxa_throw/begin_catch/end_catch/
// rethrow/allocate_exception, __gxx_personality_v0, the _Unwind_* DWARF
// machinery, and __cxa_demangle all resolve against our libc++.so + sysroot.
// Execution (exit code 0) is proven by the #34 boot gate, not here.
#include <cxxabi.h>

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <typeinfo>

namespace cerise::throwing {

struct ProbeError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

// Out-of-line + noinline so the throw crosses a real call frame and the
// unwinder must walk DWARF CFI (not a same-frame fold).
[[gnu::noinline]] void ThrowDeep(int depth) {
  if (depth == 0) {
    throw ProbeError("probe");
  }
  ThrowDeep(depth - 1);
  // Keep the frame non-trivial.
  std::puts("unreachable");
}

}  // namespace cerise::throwing

int main() {
  int caught = 0;

  // throw / catch-by-base / rethrow / catch-again.
  try {
    try {
      cerise::throwing::ThrowDeep(4);
    } catch (const std::exception& e) {
      ++caught;
      std::printf("caught: %s\n", e.what());
      throw;  // __cxa_rethrow
    }
  } catch (const cerise::throwing::ProbeError& e) {
    ++caught;
  }

  // In-process demangling of a real RTTI name (real __cxa_demangle, not the
  // old nullptr stub).
  int status = -1;
  char* demangled = abi::__cxa_demangle(
      typeid(cerise::throwing::ProbeError).name(), nullptr, nullptr, &status);
  if (status != 0 || demangled == nullptr) {
    return 2;
  }
  std::printf("typeid demangles to: %s\n", demangled);
  std::string check(demangled);
  std::free(demangled);
  if (check.find("ProbeError") == std::string::npos) {
    return 3;
  }

  return caught == 2 ? 0 : 1;
}
