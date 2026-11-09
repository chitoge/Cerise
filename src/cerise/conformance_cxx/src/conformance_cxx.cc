// Cerise runtime-conformance C++ probe. Promotes examples/cxx-throw-
// probe (which only LINKED) into a staged component that RUNS the C++ runtime on
// a real boot and asserts each result, emitting a granular CERISE-CONF-CXX-*
// marker straight to serial (zx_debug_write) per area:
//
//   * THROW-SO:  throw/catch/rethrow + catch-BY-BASE across a shared-library
//                boundary — the throw executes inside libconfthrow.so and unwinds
//                back into this main binary (the acid test for the unwinder +
//                eh_frame registration across a DT_NEEDED object).
//   * THREAD-EXC: an exception thrown AND caught inside a std::thread.
//   * DEMANGLE:  in-process abi::__cxa_demangle of a real RTTI name, asserted
//                readable (real cxa_demangle, not the old nullptr stub).
//   * RANDOM:    <random> — std::mt19937's standardized 10000th output, plus a
//                deterministic-seed binomial_distribution sequence.
//   * FS:        <filesystem> directory iteration over /pkg, asserting expected
//                entries (bin, lib, meta) are present.
#include <cxxabi.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>
#include <typeinfo>

#include <zircon/syscalls.h>

#include "throw_source.h"

namespace {

void Dbg(const char* s) { zx_debug_write(s, std::strlen(s)); }

void Fail(const char* why) {
  Dbg("CERISE-CONF-CXX-FAIL ");
  Dbg(why);
  Dbg("\n");
}

// (1) throw in libconfthrow.so, catch BY BASE in this binary, rethrow, catch again.
bool ThrowAcrossSo() {
  int caught = 0;
  try {
    try {
      cerise::conf::ThrowFromSo(4);  // throws ConfThrowError inside the .so
      Fail("throw-so-no-throw");
      return false;
    } catch (const std::exception& base) {
      // Caught by base across the .so boundary: the unwinder walked the .so's
      // eh_frame and matched std::exception's single typeinfo in libc++.so.1.
      ++caught;
      if (std::strstr(base.what(), "libconfthrow.so") == nullptr) {
        Fail("throw-so-what");
        return false;
      }
      throw;  // __cxa_rethrow
    }
  } catch (const std::runtime_error& re) {
    ++caught;
  }
  if (caught != 2) {
    Fail("throw-so-count");
    return false;
  }
  return true;
}

// (2) an exception thrown and caught inside a std::thread.
bool ThreadException() {
  std::atomic<int> caught{0};
  std::thread t([&caught] {
    try {
      throw std::logic_error("thrown-on-worker-thread");
    } catch (const std::logic_error& e) {
      if (std::strcmp(e.what(), "thrown-on-worker-thread") == 0) {
        caught.store(1);
      }
    }
  });
  t.join();
  if (caught.load() != 1) {
    Fail("thread-exc");
    return false;
  }
  return true;
}

// (3) in-process __cxa_demangle of a real RTTI name.
bool Demangle() {
  int status = -1;
  char* out = abi::__cxa_demangle(typeid(cerise::conf::ConfThrowError).name(),
                                  nullptr, nullptr, &status);
  if (status != 0 || out == nullptr) {
    Fail("demangle-status");
    return false;
  }
  std::string s(out);
  std::free(out);
  if (s.find("ConfThrowError") == std::string::npos) {
    Fail("demangle-content");
    return false;
  }
  return true;
}

// (4) <random>: mt19937 standardized output + deterministic binomial sequence.
// The binomial values are implementation-defined; captured from the vendored
// libc++ on the first boot, then hard-asserted here.
constexpr int kBinoN = 5;
// Filled in after the first-boot CERISE-CONF-CXX-RANDOM-CAPTURE line; a negative
// sentinel means "capture mode" (print + range-check only, no strict assert).
// Captured from the vendored libc++ on the first boot — mt19937(12345)
// + binomial_distribution<int>(40, 0.5), first 5 draws. Deterministic per the
// seed + libc++ algorithm; re-asserted on every boot.
constexpr int kBinoWant[kBinoN] = {25, 19, 20, 24, 22};

bool Random() {
  // mt19937 default-seeded: the 10000th consecutive output is standardized.
  std::mt19937 gen;
  for (int i = 0; i < 9999; ++i) gen();
  std::uint32_t v = gen();
  if (v != 4123659995u) {
    Fail("mt19937-10000th");
    return false;
  }
  // Deterministic-seed binomial_distribution sequence.
  std::mt19937 g2(12345u);
  std::binomial_distribution<int> bino(40, 0.5);
  int got[kBinoN];
  for (int i = 0; i < kBinoN; ++i) {
    got[i] = bino(g2);
    if (got[i] < 0 || got[i] > 40) {
      Fail("binomial-range");
      return false;
    }
  }
  char cap[128];
  std::snprintf(cap, sizeof(cap),
                "CERISE-CONF-CXX-RANDOM-CAPTURE binomial=%d,%d,%d,%d,%d\n",
                got[0], got[1], got[2], got[3], got[4]);
  Dbg(cap);
  if (kBinoWant[0] >= 0) {
    for (int i = 0; i < kBinoN; ++i) {
      if (got[i] != kBinoWant[i]) {
        Fail("binomial-values");
        return false;
      }
    }
  }
  return true;
}

// (5) <filesystem> directory iteration over /pkg.
bool Filesystem() {
  namespace fs = std::filesystem;
  std::error_code ec;
  bool have_bin = false, have_lib = false, have_meta = false;
  int count = 0;
  for (fs::directory_iterator it("/pkg", ec), end; it != end; it.increment(ec)) {
    if (ec) {
      Fail("fs-iterate");
      return false;
    }
    ++count;
    std::string name = it->path().filename().string();
    if (name == "bin") have_bin = true;
    else if (name == "lib") have_lib = true;
    else if (name == "meta") have_meta = true;
  }
  if (count == 0) {
    Fail("fs-empty");
    return false;
  }
  if (!(have_bin && have_lib && have_meta)) {
    char why[96];
    std::snprintf(why, sizeof(why), "fs-missing bin=%d lib=%d meta=%d",
                  have_bin, have_lib, have_meta);
    Fail(why);
    return false;
  }
  return true;
}

}  // namespace

int main() {
  Dbg("CERISE-CONF-CXX-START\n");
  if (!ThrowAcrossSo()) return 1;
  Dbg("CERISE-CONF-CXX-THROW-SO-OK\n");
  if (!ThreadException()) return 1;
  Dbg("CERISE-CONF-CXX-THREAD-EXC-OK\n");
  if (!Demangle()) return 1;
  Dbg("CERISE-CONF-CXX-DEMANGLE-OK\n");
  if (!Random()) return 1;
  Dbg("CERISE-CONF-CXX-RANDOM-OK\n");
  if (!Filesystem()) return 1;
  Dbg("CERISE-CONF-CXX-FS-OK\n");
  Dbg("CERISE-CONF-CXX-DONE\n");
  return 0;
}
