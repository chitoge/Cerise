// Cerise: libm stub for x86_64-unknown-fuchsia.
// Fuchsia's musl libc.so includes all math functions; programs that link -lm
// get them from libc.so at runtime. This stub .so satisfies the linker's -lm
// requirement without duplicating the implementations.
