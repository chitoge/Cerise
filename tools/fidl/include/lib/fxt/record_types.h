#ifndef LIB_FXT_RECORD_TYPES_H_
#define LIB_FXT_RECORD_TYPES_H_

#include <stddef.h>
#include <stdint.h>

namespace fxt {

template <typename Enum>
constexpr auto ToUnderlyingType(Enum value) {
  return static_cast<decltype(static_cast<uint64_t>(value))>(value);
}

struct Koid {
  uint64_t koid = 0;

  constexpr Koid() = default;
  constexpr explicit Koid(uint64_t value) : koid(value) {}

  constexpr operator uint64_t() const { return koid; }
};

struct Pointer {
  uintptr_t value = 0;

  constexpr Pointer() = default;
  constexpr explicit Pointer(uintptr_t pointer) : value(pointer) {}

  constexpr operator uint64_t() const { return value; }
};

class WordSize {
 public:
  constexpr WordSize() = default;
  constexpr explicit WordSize(uint16_t words) : words_(words) {}

  static constexpr WordSize FromBytes(size_t bytes) {
    return WordSize(static_cast<uint16_t>((bytes + sizeof(uint64_t) - 1) / sizeof(uint64_t)));
  }

  constexpr uint16_t word_count() const { return words_; }

 private:
  uint16_t words_ = 0;
};

enum class RecordType : uint8_t {
  kMetadata = 0,
  kInitialization = 1,
  kString = 2,
  kKernelObject = 3,
  kEvent = 4,
  kBlob = 5,
};

enum class EventType : uint8_t {
  kInstant = 0,
  kCounter = 1,
  kDurationBegin = 2,
  kDurationEnd = 3,
  kDurationComplete = 4,
  kFlowBegin = 5,
  kFlowStep = 6,
  kFlowEnd = 7,
};

template <unsigned Shift, unsigned Width>
struct Field {
  template <typename T>
  static constexpr T Get(uint64_t value) {
    constexpr uint64_t mask = Width == 64 ? ~uint64_t{0} : ((uint64_t{1} << Width) - 1u);
    return static_cast<T>((value >> Shift) & mask);
  }

  static constexpr uint64_t Make(uint64_t value) {
    constexpr uint64_t mask = Width == 64 ? ~uint64_t{0} : ((uint64_t{1} << Width) - 1u);
    return (value & mask) << Shift;
  }
};

struct RecordFields {
  using Type = Field<0, 4>;
  using RecordSize = Field<4, 12>;
};

struct LargeRecordFields {
  using RecordSize = Field<4, 20>;
};

struct EventRecordFields {
  using EventType = Field<16, 4>;
  using ArgumentCount = Field<20, 8>;
  using ThreadRef = Field<28, 12>;
  using CategoryStringRef = Field<40, 12>;
  using NameStringRef = Field<52, 12>;
};

constexpr uint64_t MakeHeader(RecordType type, WordSize record_size) {
  return RecordFields::Type::Make(ToUnderlyingType(type)) |
         RecordFields::RecordSize::Make(record_size.word_count());
}

}  // namespace fxt

#endif  // LIB_FXT_RECORD_TYPES_H_