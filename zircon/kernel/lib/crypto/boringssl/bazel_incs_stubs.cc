// Copyright 2025 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// Bazel build stub for incs-and-stubs.cc.
// In the Bazel build, SHA256 is provided by @boringssl//:kernel_crypto.
// This file provides only the OPENSSL_cleanse symbol which is not in kernel_crypto.

#include <stddef.h>
#include <string.h>

void OPENSSL_cleanse(void *ptr, size_t len) {
  if (len != 0) {
    memset(ptr, 0, len);
  }
}
