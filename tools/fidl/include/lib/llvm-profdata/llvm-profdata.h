#ifndef TOOLS_FIDL_INCLUDE_LIB_LLVM_PROFDATA_LLVM_PROFDATA_H_
#define TOOLS_FIDL_INCLUDE_LIB_LLVM_PROFDATA_LLVM_PROFDATA_H_

#include <cstddef>
#include <span>
#include <string_view>

class LlvmProfdata {
 public:
  struct LiveData {
    std::span<std::byte> counters;
    std::span<std::byte> bitmap;
  };

  static size_t LiveDataCountersAlignment() { return sizeof(uint64_t); }

  void Init(std::span<const std::byte> build_id) {}

  size_t size_bytes() const { return 0; }
  size_t counters_offset() const { return 0; }
  size_t counters_size_bytes() const { return 0; }
  static bool UsingSingleByteCounters() { return false; }
  size_t bitmap_offset() const { return 0; }
  size_t bitmap_size_bytes() const { return 0; }

  static std::span<const std::byte> BuildIdFromRawProfile(std::span<const std::byte> data) {
    return {};
  }

  bool Match(std::span<const std::byte> data) { return false; }

  LiveData WriteFixedData(std::span<std::byte> data) { return {}; }
  LiveData VerifyMatch(std::span<std::byte> data) { return {}; }
  void CopyLiveData(LiveData data) {}
  void MergeLiveData(LiveData data) {}
  static void MergeLiveData(LiveData to, LiveData from) {}
  static void UseLiveData(LiveData data) {}
  static void UseLinkTimeLiveData() {}

  static constexpr size_t kAlign = 8;
  static constexpr std::string_view kDataSinkName = "llvm-profile";
  static constexpr std::string_view kFileSuffix = ".profraw";
  static constexpr std::string_view kAnnounce = "LLVM Profile";
};

#endif  // TOOLS_FIDL_INCLUDE_LIB_LLVM_PROFDATA_LLVM_PROFDATA_H_