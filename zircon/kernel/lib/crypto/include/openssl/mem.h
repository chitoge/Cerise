// Minimal BoringSSL memory stubs for the kernel crypto build.
#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void OPENSSL_cleanse(void* ptr, size_t len);

#ifdef __cplusplus
}
#endif
