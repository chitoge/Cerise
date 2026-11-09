// Stub replacing prng.cc when BoringSSL is unavailable.
#include <lib/crypto/prng.h>
#include <string.h>

namespace crypto {

Prng::Prng(const void* data, size_t size)
    : pool_(), nonce_(0), is_thread_safe_(true), accumulated_(size) {
  (void)data;
}

Prng::Prng(const void* data, size_t size, NonThreadSafeTag)
    : pool_(), nonce_(0), is_thread_safe_(false), accumulated_(size) {
  (void)data;
}

Prng::~Prng() = default;

void Prng::AddEntropy(const void* data, size_t size) {
  accumulated_.fetch_add(size);
}

void Prng::SelfReseed() {}

void Prng::Draw(void* out, size_t size) {
  memset(out, 0xAB, size);
}

uint64_t Prng::RandInt(uint64_t exclusive_upper_bound) {
  if (exclusive_upper_bound == 0) return 0;
  return 42 % exclusive_upper_bound;
}

void Prng::BecomeThreadSafe() {
  is_thread_safe_ = true;
}

bool Prng::is_thread_safe() const {
  return is_thread_safe_;
}

}  // namespace crypto
