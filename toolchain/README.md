# Toolchain Package

This package is the Bazel-native owner for the LLVM and linker configuration.

Bootstrap strategy:

- use `hermeticbuild/hermetic-llvm` as the Bazel-managed LLVM provider,
- register Linux x86_64 exec and target toolchains through `@llvm_toolchains`,
- expose public LLVM binaries through `@llvm-project` aliases where direct tool invocation is needed,
- and keep system compiler paths out of the graph.

Details:

- `MODULE.bazel` selects `hermetic-llvm` `0.8.3`.
- `@llvm_toolchains//:linux_x86_64/default_tools` materializes under Bazel.
- The local `//toolchain` aliases resolve against the public `@llvm-project` targets for `clang`, `lld`, `llvm-ar`, and `llvm-nm`.
- The chosen LLVM path does not depend on a host `libxml2.so.2` runtime library.
- `//toolchain` defines repo-owned Zircon environment toolchains for x64 kernel, phys, and EFI configuration. These provide named Zircon feature composition and generated manifests for kernel rules to consume through Bazel toolchain resolution; they do not replace the LLVM C++ toolchain.

Native C/C++ rules request `//toolchain:zircon_kernel_toolchain_type` or its phys/EFI sibling and consume `ZirconToolchainInfo` rather than copying `_X64_*` flag lists into each target.
