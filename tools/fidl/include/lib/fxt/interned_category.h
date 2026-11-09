#ifndef LIB_FXT_INTERNED_CATEGORY_H_
#define LIB_FXT_INTERNED_CATEGORY_H_

#include <stddef.h>
#include <stdint.h>

namespace fxt {

class InternedCategory {
 public:
  static constexpr uint32_t kInvalidIndex = 0xffffffffu;

  struct EmptyRange {
    constexpr const InternedCategory* begin() const { return nullptr; }
    constexpr const InternedCategory* end() const { return nullptr; }
  };

  constexpr InternedCategory() = default;
  constexpr explicit InternedCategory(const char* string, uint32_t index = kInvalidIndex)
      : string_(string), index_(index) {}

  constexpr uint32_t index() const { return index_; }
  constexpr const char* label() const { return string_; }
  constexpr const char* string() const { return string_; }
  constexpr void SetIndex(uint32_t index) const { index_ = index; }

  static constexpr EmptyRange Iterate() { return {}; }

 private:
  const char* string_ = "";
  mutable uint32_t index_ = kInvalidIndex;
};

constexpr InternedCategory operator""_category(const char* string, size_t) {
  return InternedCategory(string);
}

}  // namespace fxt

#endif  // LIB_FXT_INTERNED_CATEGORY_H_