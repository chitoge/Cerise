// host-side proof that the exact vendored libcxxabi demangler
// sources compiled into libc++.so (cxa_demangle.cpp + demangle/ItaniumNodes.def
// et al.) actually demangle Itanium-mangled names. Target execution is proven
// separately by the runtime-conformance boot gate (#34); this pins the source
// wiring (the .def textual header staging) so it can never silently regress to
// the old nullptr stub.
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" char* __cxa_demangle(const char* mangled_name, char* output_buffer,
                                size_t* length, int* status);

namespace {

bool Check(const char* mangled, const char* expect_substr) {
  int status = -99;
  char* out = __cxa_demangle(mangled, nullptr, nullptr, &status);
  if (status != 0 || out == nullptr) {
    std::fprintf(stderr, "FAIL: __cxa_demangle(%s) status=%d out=%p\n", mangled,
                 status, static_cast<void*>(out));
    return false;
  }
  std::printf("%s -> %s\n", mangled, out);
  const bool ok = std::strstr(out, expect_substr) != nullptr;
  if (!ok) {
    std::fprintf(stderr, "FAIL: expected substring \"%s\" in \"%s\"\n",
                 expect_substr, out);
  }
  std::free(out);
  return ok;
}

}  // namespace

int main() {
  bool ok = true;
  ok &= Check("_ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backEOi",
              "vector<int, std::__1::allocator<int>");
  ok &= Check("_ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backEOi", "push_back");
  ok &= Check("_Z4sqrtd", "sqrt(double)");
  ok &= Check("_ZN6cerise8throwing8ProbeFooD2Ev", "cerise::throwing::ProbeFoo::~ProbeFoo()");
  // Invalid input must fail cleanly (status -2), not crash.
  int status = 0;
  char* out = __cxa_demangle("not_a_mangled_name", nullptr, nullptr, &status);
  if (out != nullptr || status != -2) {
    std::fprintf(stderr, "FAIL: invalid-input handling: out=%p status=%d\n",
                 static_cast<void*>(out), status);
    ok = false;
  }
  if (!ok) return 1;
  std::puts("PASS: in-tree libcxxabi demangler sources are functional");
  return 0;
}
