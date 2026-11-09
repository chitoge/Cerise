#ifndef LIB_FXT_INTERNED_STRING_H_
#define LIB_FXT_INTERNED_STRING_H_

#include <stddef.h>
#include <stdint.h>

namespace fxt {

enum class RefType {
  kId,
  kInline,
};

class InternedString {
 public:
  static constexpr uint16_t kInvalidId = 0;
  static constexpr size_t kMaxStringLength = 0xffff;

  struct EmptyRange {
    constexpr const InternedString* begin() const { return nullptr; }
    constexpr const InternedString* end() const { return nullptr; }
  };

  constexpr InternedString() = default;
  constexpr explicit InternedString(const char* string, uint16_t id = kInvalidId)
      : string_(string), id_(id) {}

  constexpr uint16_t id() const { return id_; }
  constexpr const char* string() const { return string_; }
  static constexpr EmptyRange Iterate() { return {}; }

 private:
  const char* string_ = "";
  uint16_t id_ = kInvalidId;
};

namespace internal {

template <size_t N>
struct FixedString {
  char value[N];

  constexpr FixedString(const char (&string)[N]) : value{} {
    for (size_t i = 0; i < N; ++i) {
      value[i] = string[i];
    }
  }
};

template <char... Chars>
struct InternedStringStorage {
  inline static constexpr char string[] = {Chars..., '\0'};
  inline static constexpr InternedString interned_string{string};
};

template <FixedString String>
struct LiteralInternedStringStorage {
  inline static constexpr auto string = String;
  inline static constexpr InternedString interned_string{string.value};
};

}  // namespace internal

template <internal::FixedString String>
constexpr const InternedString& operator""_intern() {
  return internal::LiteralInternedStringStorage<String>::interned_string;
}

}  // namespace fxt

#endif  // LIB_FXT_INTERNED_STRING_H_