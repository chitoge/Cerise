#ifndef SRC_LIB_FXL_STRINGS_UTF_CODECS_H_
#define SRC_LIB_FXL_STRINGS_UTF_CODECS_H_

#include <string_view>

namespace fxl {

inline bool IsStringUTF8(std::string_view value) {
    size_t index = 0;
    while (index < value.size()) {
        unsigned char byte = static_cast<unsigned char>(value[index]);
        if (byte <= 0x7F) {
            ++index;
            continue;
        }

        size_t continuation_count = 0;
        uint32_t code_point = 0;
        if ((byte & 0xE0) == 0xC0) {
            continuation_count = 1;
            code_point = byte & 0x1F;
            if (code_point == 0) {
                return false;
            }
        } else if ((byte & 0xF0) == 0xE0) {
            continuation_count = 2;
            code_point = byte & 0x0F;
        } else if ((byte & 0xF8) == 0xF0) {
            continuation_count = 3;
            code_point = byte & 0x07;
        } else {
            return false;
        }

        if (index + continuation_count >= value.size()) {
            return false;
        }

        for (size_t offset = 1; offset <= continuation_count; ++offset) {
            unsigned char continuation = static_cast<unsigned char>(value[index + offset]);
            if ((continuation & 0xC0) != 0x80) {
                return false;
            }
            code_point = (code_point << 6) | (continuation & 0x3F);
        }

        if ((continuation_count == 1 && code_point < 0x80) ||
            (continuation_count == 2 && code_point < 0x800) ||
            (continuation_count == 3 && code_point < 0x10000) ||
            code_point > 0x10FFFF ||
            (code_point >= 0xD800 && code_point <= 0xDFFF)) {
            return false;
        }

        index += continuation_count + 1;
    }

    return true;
}

}  // namespace fxl

#endif  // SRC_LIB_FXL_STRINGS_UTF_CODECS_H_