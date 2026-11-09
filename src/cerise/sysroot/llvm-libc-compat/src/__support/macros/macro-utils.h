// Cerise compat shim. LLVM_LIBC_STRINGIFY was
// removed from the repo's newer @llvm-project llvm-libc, but Fuchsia's
// sdk/lib/c (pinned to Fuchsia's clang's llvm-libc) still includes
// <src/__support/macros/macro-utils.h> for it (e.g. asm-linkage.h). Provide the
// stable macro so the Fuchsia C++ libc/runtime body compiles against the repo's
// llvm-libc. Other macros (LIBC_NAMESPACE, ...) come from config.h.
#ifndef LLVM_LIBC_SRC___SUPPORT_MACROS_MACRO_UTILS_H
#define LLVM_LIBC_SRC___SUPPORT_MACROS_MACRO_UTILS_H

#define LLVM_LIBC_STRINGIFY_IMPL(arg) #arg
#define LLVM_LIBC_STRINGIFY(arg) LLVM_LIBC_STRINGIFY_IMPL(arg)

#endif // LLVM_LIBC_SRC___SUPPORT_MACROS_MACRO_UTILS_H
