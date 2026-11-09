// Kernel openssl/sha.h stub with BoringSSL-compatible definitions.
//
// This file replaces BoringSSL's sha.h.  When it is found first on the
// include path OPENSSL_HEADER_SHA_H prevents BoringSSL's sha.h from being
// re-included.  The SHA-256 block is guarded with OPENSSL_HEADER_SHA2_H so
// that if BoringSSL's sha2.h was already included before this file, we do not
// redefine sha256_state_st.
//
// SHA-256/chacha real implementations come from:
//   external/boringssl+/crypto/sha/sha256.cc   (compiled in same genrule)
//   external/boringssl+/crypto/chacha/chacha.cc (compiled in same genrule)
#pragma once
#define OPENSSL_HEADER_SHA_H   // suppress boringssl/include/openssl/sha.h

#include <stddef.h>
#include <stdint.h>

// ---------- SHA-1 (kernel uses no-op stubs; type must match BoringSSL) ------

#define SHA_CBLOCK 64
#define SHA1_CBLOCK 64
#define SHA_DIGEST_LENGTH 20
#define SHA1_DIGEST_LENGTH 20

struct sha_state_st {
    uint32_t h[5], Nl, Nh;
    uint8_t data[SHA_CBLOCK];
    unsigned num;
};
typedef struct sha_state_st SHA_CTX;

#ifdef __cplusplus
static inline int SHA1_Init(SHA_CTX* c) { (void)c; return 1; }
static inline int SHA1_Update(SHA_CTX* c, const void* d, size_t n) {
    (void)c; (void)d; (void)n; return 1;
}
static inline int SHA1_Final(uint8_t* m, SHA_CTX* c) { (void)m; (void)c; return 1; }
#endif

// ---------- SHA-224/256 (real impl; guard avoids conflict with sha2.h) -------
// sha2.h sets OPENSSL_HEADER_SHA2_H; if it was included first the struct and
// macros below are already defined and we must skip them.

#ifndef OPENSSL_HEADER_SHA2_H
#define OPENSSL_HEADER_SHA2_H  // claim sha2.h to prevent future inclusion

#define SHA224_CBLOCK 64
#define SHA224_DIGEST_LENGTH 28
#define SHA256_CBLOCK 64
#define SHA256_DIGEST_LENGTH 32

struct sha256_state_st {
    uint32_t h[8];
    uint32_t Nl, Nh;
    uint8_t data[SHA256_CBLOCK];
    unsigned num, md_len;
};
typedef struct sha256_state_st SHA256_CTX;

#endif // OPENSSL_HEADER_SHA2_H

// ---------- SHA-384/512 (bcm_interface.h declaration constants) --------------
#define SHA384_CBLOCK 128
#define SHA384_DIGEST_LENGTH 48
#define SHA512_CBLOCK 128
#define SHA512_DIGEST_LENGTH 64
#define SHA512_256_DIGEST_LENGTH 32

// ---------- SHA-256/224 function declarations --------------------------------
#ifdef __cplusplus
extern "C" {
#endif

int SHA224_Init(SHA256_CTX* sha);
int SHA224_Update(SHA256_CTX* sha, const void* data, size_t len);
int SHA224_Final(uint8_t* out, SHA256_CTX* sha);

int SHA256_Init(SHA256_CTX* sha);
int SHA256_Update(SHA256_CTX* sha, const void* data, size_t len);
int SHA256_Final(uint8_t* out, SHA256_CTX* sha);
uint8_t* SHA256(const uint8_t* d, size_t n, uint8_t* md);

#ifdef __cplusplus
}
#endif
