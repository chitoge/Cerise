#ifndef LIB_FXT_FIELDS_H_
#define LIB_FXT_FIELDS_H_

#include <lib/fxt/record_types.h>

namespace fxt {

enum class LargeRecordType : uint8_t {
  kBlob = 0,
};

enum class LargeBlobFormat : uint8_t {
  kMetadata = 0,
};

struct LargeBlobFields {
  using BlobFormat = Field<24, 4>;
};

constexpr uint64_t MakeLargeHeader(LargeRecordType type, WordSize record_size) {
  return RecordFields::Type::Make(15) | Field<24, 4>::Make(ToUnderlyingType(type)) |
         LargeRecordFields::RecordSize::Make(record_size.word_count());
}

}  // namespace fxt

#endif  // LIB_FXT_FIELDS_H_
