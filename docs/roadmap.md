# Roadmap

Cerise is under active development. This page lists capabilities that are
**planned but not yet implemented**, so you know where the system is headed.
Items here describe intended direction, not shipped features; each will be
documented properly as it lands.

## Test instrumentation

The build already ships the tools these depend on — the hermetic LLVM toolchain
includes `llvm-cov`, `llvm-profdata`, and `sancov` — so the work is wiring, not
new dependencies.

### Code coverage

Coverage reporting over the host test suite, produced with `bazel coverage` and
the toolchain's `llvm-cov` / `llvm-profdata`, aggregated into an lcov report and
published alongside continuous integration. This gives per-line coverage of the
Cerise-original libraries and the vendored test suites that run on the host.

### Sanitizers (host)

Opt-in Bazel configurations that compile the host tests and tools with the LLVM
sanitizers — **AddressSanitizer** (memory-safety) and **UndefinedBehaviorSanitizer**
(undefined behavior) — to catch defects in the C/C++ and Rust code that runs on
the build host.

### Sanitizers (on target)

An instrumented system image — userland built with AddressSanitizer, and the
kernel built with KernelAddressSanitizer — booted under the live-boot test
harness. Sanitizer reports surface on the serial console, so a boot that trips a
sanitizer fails the test the same way a kernel panic does: an *"ASan-clean
boot"* gate over the running system rather than only over host unit tests.

### Coverage (on target)

Collecting coverage from a booted image: the instrumented guest writes profile
data, the boot harness extracts it after the run, and `llvm-profdata` /
`llvm-cov` turn it into a report — coverage of the code paths a real boot
exercises, complementing host-level coverage.

---

Have a request or want to help with one of these? Open an issue.
