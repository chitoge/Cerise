#ifndef LIB_FXT_TRACE_BASE_H_
#define LIB_FXT_TRACE_BASE_H_

#include <lib/fxt/interned_category.h>
#include <lib/fxt/interned_string.h>

#define FXT_CONCATENATE_IMPL(a, b) a##b
#define FXT_CONCATENATE(a, b) FXT_CONCATENATE_IMPL(a, b)

#define FXT_INTERN_CATEGORY(category) (::fxt::InternedCategory(category))
#define FXT_INTERN_STRING(string) (::fxt::InternedString(string))

#define FXT_EVENT_COMMON(...) \
  do {                     \
  } while (false)

#define FXT_KERNEL_OBJECT(...) \
  do {                      \
  } while (false)

#define FXT_KERNEL_OBJECT_ALWAYS(...) \
  do {                             \
  } while (false)

#define FXT_BEGIN_SCOPE(...) (::fxt::Scope{})
#define FXT_END_SCOPE(...) (::fxt::Scope{})

#define FXT_MAP_LIST_ARGS(macro, ...)
#define FXT_MAKE_ARGUMENT(...) __VA_ARGS__

#define FXT_ANNOTATED_VALUE(acquire_or_assert_expression, value_expression) (value_expression)

namespace fxt {

class Scope {
 public:
  constexpr Scope() = default;

  template <typename T>
  constexpr Scope(T&&) {}

  template <typename T>
  constexpr Scope& operator=(T&&) {
    return *this;
  }

  constexpr auto Completer() const { return []() {}; }

  constexpr void End() const {}
};

}  // namespace fxt

#endif  // LIB_FXT_TRACE_BASE_H_