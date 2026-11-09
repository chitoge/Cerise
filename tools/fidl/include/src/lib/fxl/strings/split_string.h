#ifndef SRC_LIB_FXL_STRINGS_SPLIT_STRING_H_
#define SRC_LIB_FXL_STRINGS_SPLIT_STRING_H_

#include <string_view>
#include <vector>

namespace fxl {

enum WhiteSpaceHandling {
    kKeepWhitespace,
    kTrimWhitespace,
};

enum SplitResult {
    kSplitWantAll,
    kSplitWantNonEmpty,
};

namespace internal {

inline bool IsWhitespace(char ch) {
    switch (ch) {
        case ' ':
        case '\n':
        case '\r':
        case '\t':
        case '\f':
        case '\v':
            return true;
        default:
            return false;
    }
}

inline std::string_view Trim(std::string_view value) {
    while (!value.empty() && IsWhitespace(value.front())) {
        value.remove_prefix(1);
    }
    while (!value.empty() && IsWhitespace(value.back())) {
        value.remove_suffix(1);
    }
    return value;
}

}  // namespace internal

inline std::vector<std::string_view> SplitString(
    std::string_view input,
    std::string_view separators,
    WhiteSpaceHandling whitespace,
    SplitResult split_result) {
    std::vector<std::string_view> parts;
    size_t start = 0;

    while (start <= input.size()) {
        size_t end = input.find_first_of(separators, start);
        bool at_end = end == std::string_view::npos;
        if (at_end) {
            end = input.size();
        }

        std::string_view part = input.substr(start, end - start);
        if (whitespace == kTrimWhitespace) {
            part = internal::Trim(part);
        }
        if (split_result == kSplitWantAll || !part.empty()) {
            parts.push_back(part);
        }

        if (at_end) {
            break;
        }
        start = end + 1;
    }

    return parts;
}

}  // namespace fxl

#endif  // SRC_LIB_FXL_STRINGS_SPLIT_STRING_H_