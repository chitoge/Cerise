// Kernel openssl/chacha.h — forward declaration for boringssl CRYPTO_chacha_20.
// The inline stub is removed here; the real implementation comes from
// external/boringssl+/crypto/chacha/chacha.cc compiled in the same genrule.
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void CRYPTO_chacha_20(uint8_t* out, const uint8_t* in, size_t in_len,
                      const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter);

#ifdef __cplusplus
}
#endif
