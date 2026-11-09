# SDK Package Skeleton

This package is the first Bazel-native owner for the userland development surface.

Current scope:

- expose the imported `zircon/system/ulib/zx` slice,
- pair it with ABI and public Zircon header surfaces,
- and keep the first SDK boundary narrow enough to support a future Bazel-built app without importing libc, fdio, or async frameworks yet.

Current targets:

- `//sdk:libzx_sources`
- `//sdk:libzx_headers`
- `//sdk:userland_core_headers`
- `//sdk:userland_core_sources`

Deferred for later milestones:

- libc and dynamic linker integration,
- compiler-rt linkage integration,
- and full `ZirconSdkInfo` provider emission with compiled libraries.
