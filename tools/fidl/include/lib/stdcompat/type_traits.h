#ifndef LIB_STDCOMPAT_TYPE_TRAITS_H_
#define LIB_STDCOMPAT_TYPE_TRAITS_H_

#include <type_traits>

namespace cpp20 {

using std::is_unbounded_array;
using std::is_unbounded_array_v;
using std::remove_cvref;
using std::remove_cvref_t;
using std::type_identity;
using std::type_identity_t;

}  // namespace cpp20

#endif  // LIB_STDCOMPAT_TYPE_TRAITS_H_