#ifndef LIB_FXT_ARGUMENT_H_
#define LIB_FXT_ARGUMENT_H_

#include <stdint.h>

#include <lib/fxt/string_ref.h>

namespace fxt {

enum class ArgumentType {
  kInt32,
  kUint32,
  kInt64,
  kUint64,
};

template <ArgumentType Type = ArgumentType::kUint64, RefType NameRefType = RefType::kId>
struct Argument {
  constexpr Argument() = default;

  template <typename Value>
  constexpr Argument(StringRef<NameRefType> name, Value value)
      : name(name), value(Encode(value)) {}

  template <typename Value>
  constexpr Argument(const InternedString& interned_name, Value value)
      : name(StringRef<NameRefType>(interned_name)), value(Encode(value)) {}

  constexpr uint64_t Header() const { return value; }

 private:
  template <typename Value>
  static constexpr auto Encode(const Value& value) -> decltype(value.HeaderEntry(), uint64_t{}) {
    return static_cast<uint64_t>(value.HeaderEntry());
  }

  template <typename Value>
    requires (!requires(const Value& candidate) { candidate.HeaderEntry(); })
  static constexpr uint64_t Encode(const Value& value) {
    return static_cast<uint64_t>(value);
  }

 public:

  StringRef<NameRefType> name{};
  uint64_t value{};
};

template <typename Value>
Argument(StringRef<RefType::kId>, Value) -> Argument<ArgumentType::kUint64, RefType::kId>;

template <typename Value>
Argument(const InternedString&, Value) -> Argument<ArgumentType::kUint64, RefType::kId>;

}  // namespace fxt

#endif  // LIB_FXT_ARGUMENT_H_