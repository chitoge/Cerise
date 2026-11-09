# Vendored llvm-libc shared headers (Cerise libc sysroot assembly)

Fuchsia's libc is a musl + llvm-libc hybrid. musl's public headers (e.g.
`features.h`) `#include "__llvm-libc-common.h"`, a shared macro header that is
part of llvm-libc, not musl. It lives in the LLVM tree at
`libc/include/__llvm-libc-common.h` but is **not** part of the
`@llvm-project//libc:libc_headers` Bazel target and is not individually
referenceable, so it is vendored here for the Cerise libc sysroot assembly
for the shared C runtime.

- Source: `@llvm-project` (the vendored LLVM overlay), `libc/include/__llvm-libc-common.h`.
- License: Apache License v2.0 WITH LLVM-exception (header retained verbatim).
- Provision: musl-first. The musl include dir wins for standard headers; this
  only supplies the llvm-libc shared header(s) musl references.

Keep this list minimal — add an llvm-libc shared header only when a vendored
musl header actually pulls it.
