#include <type_traits>

#ifndef _LIBCPP_VERSION
#error "expected libc++ headers from the Zircon toolchain"
#endif

namespace {

struct probe_type {};

static_assert(std::is_same_v<std::remove_cvref_t<const probe_type&>, probe_type>);

}  // namespace
