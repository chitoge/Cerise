#include <lib/zbitl/decompress.h>

namespace zbitl::decompress {

size_t OneShot::GetScratchSize() { return 1; }

OneShot::Context* OneShot::Init(void* scratch_space, size_t size) {
  return reinterpret_cast<Context*>(scratch_space);
}

fit::result<std::string_view> OneShot::DecompressImpl(Context* ctx, std::span<std::byte> out,
                                                      ByteView in) {
  return fit::error{"compressed ZBI payloads are not enabled in this Bazel phys build"};
}

}  // namespace zbitl::decompress
