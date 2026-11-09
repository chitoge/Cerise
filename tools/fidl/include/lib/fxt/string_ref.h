#ifndef LIB_FXT_STRING_REF_H_
#define LIB_FXT_STRING_REF_H_

#include <stddef.h>
#include <stdint.h>

#include <lib/fxt/interned_string.h>

namespace fxt {

template <RefType>
class StringRef;

template <>
class StringRef<RefType::kId> {
 public:
  constexpr StringRef() = default;
  constexpr explicit StringRef(uint16_t id) : id_(id) {}
  constexpr StringRef(const InternedString& interned) : id_(interned.id()) {}

  constexpr uint16_t id() const { return id_; }
  constexpr uint64_t HeaderEntry() const { return id_; }

 private:
  uint16_t id_ = InternedString::kInvalidId;
};

template <>
class StringRef<RefType::kInline> {
 public:
  constexpr StringRef() = default;
  constexpr explicit StringRef(const char* string) : string_(string) {}
  constexpr StringRef(const char* string, size_t length) : string_(string), length_(length) {}
  constexpr StringRef(const InternedString& interned) : string_(interned.string()) {}

  constexpr const char* string() const { return string_; }
  constexpr size_t length() const { return length_; }
  constexpr uint64_t HeaderEntry() const { return 0; }

 private:
  const char* string_ = "";
  size_t length_ = 0;
};

StringRef(uint16_t) -> StringRef<RefType::kId>;
StringRef(const InternedString&) -> StringRef<RefType::kId>;
StringRef(const char*) -> StringRef<RefType::kInline>;
StringRef(const char*, size_t) -> StringRef<RefType::kInline>;

}  // namespace fxt

#endif  // LIB_FXT_STRING_REF_H_