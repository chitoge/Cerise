# ABI Package Skeleton

This package is the first Bazel-native owner for the Zircon ABI and syscall source surfaces.

Current scope:

- re-export the curated upstream FIDL compiler sources,
- re-export public Zircon ABI headers,
- re-export zither sources,
- and re-export the vDSO FIDL source set.

Current executable ownership:

- `//abi:zircon_abi` emits deterministic staged ABI input directories for the imported vDSO FIDL and public header surfaces.
- `//abi:zircon_abi` also emits a `fidlc` response file, a structured library manifest, and the workspace's first executable ABI input boundary through `ZirconAbiInfo`.
- `//abi:zircon_abi_boundary_check` validates the staged inputs and generated `fidlc` metadata.
- `//abi:zx_syscall_headers` runs a Bazel-owned zither kernel backend against `//abi:zircon_abi_fidl_ir` and exposes generated `lib/syscalls/*` headers and includes.
- `//abi:zx_syscall_headers_compile_check` compiles a small C++ probe against the generated `zx-syscall-numbers.h` surface.

This package is now a strict `fidlc` handoff boundary with one owned zither execution slice for kernel syscall headers. Broader upstream zither coverage still depends on importing more of Fuchsia's Go-side host-tool surface.
