#ifndef LIB_DEVICETREE_DEVICETREE_H_
#define LIB_DEVICETREE_DEVICETREE_H_

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <tuple>

namespace devicetree {

class Property {
 public:
  using StringList = std::span<const std::string_view>;

  std::optional<StringList> AsStringList() const { return std::nullopt; }
  std::optional<uint32_t> AsUint32() const { return std::nullopt; }
};

class PropertyDecoder {
 public:
  std::optional<Property> FindProperty(std::string_view) const { return std::nullopt; }

  template <typename... Names>
  auto FindProperties(Names&&...) const {
    return std::tuple<std::optional<Property>, std::optional<Property>>{};
  }
};

}  // namespace devicetree

#endif  // LIB_DEVICETREE_DEVICETREE_H_