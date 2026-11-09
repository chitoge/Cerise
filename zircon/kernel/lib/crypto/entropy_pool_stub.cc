// Stub replacing entropy_pool.cc when BoringSSL is unavailable.
#include <lib/crypto/entropy_pool.h>
#include <string.h>

namespace crypto {

EntropyPool::EntropyPool(EntropyPool&& other) noexcept { (*this) = ktl::move(other); }

EntropyPool& EntropyPool::operator=(EntropyPool&& other) noexcept {
  memcpy(contents_.data(), other.contents_.data(), contents_.size());
  memset(other.contents_.data(), kShredValue, other.contents_.size());
  return *this;
}

EntropyPool::~EntropyPool() {
  memset(contents_.data(), kShredValue, contents_.size());
}

void EntropyPool::Add(std::span<const uint8_t> entropy) {
  // Trivial mix: XOR into contents.
  for (size_t i = 0; i < entropy.size() && i < contents_.size(); ++i) {
    contents_[i] ^= entropy[i];
  }
}

size_t EntropyPool::AddFromDigest(std::span<const uint8_t> source) {
  Add(source);
  return 32;
}

}  // namespace crypto
