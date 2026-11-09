#include <hwreg/asm.h>

#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>

namespace {

std::string ToMacroIdentifier(std::string_view name) {
  std::string result;
  result.reserve(name.size());
  for (unsigned char ch : name) {
    if (std::isalnum(ch) || ch == '_') {
      result.push_back(static_cast<char>(std::toupper(ch)));
    } else {
      result.push_back('_');
    }
  }
  return result;
}

std::string HeaderGuard(std::string_view include_name) {
  std::string guard = ToMacroIdentifier(include_name);
  if (guard.empty() || guard.back() != '_') {
    guard.push_back('_');
  }
  return guard;
}

uint64_t MaskForWidth(uint32_t width) {
  if (width >= 64) {
    return ~uint64_t{0};
  }
  return (uint64_t{1} << width) - 1;
}

std::string HexLiteral(uint64_t value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << std::uppercase << value;
  return stream.str();
}

}  // namespace

namespace hwreg {

AsmHeader& AsmHeader::Line(std::initializer_list<std::string_view> strings) {
  for (std::string_view string : strings) {
    body_.append(string.data(), string.size());
  }
  body_.push_back('\n');
  return *this;
}

AsmHeader& AsmHeader::Macro(std::string_view name, std::string_view value) {
  return Line({"#define ", name, " ", value});
}

AsmHeader& AsmHeader::Macro(std::string_view name, uint64_t value) {
  return Macro(name, HexLiteral(value));
}

std::string AsmHeader::Output(std::string_view include_name) {
  const std::string guard = HeaderGuard(include_name);

  std::string output;
  output.reserve(body_.size() + guard.size() * 3 + include_name.size() + 64);
  output.append("#ifndef ");
  output.append(guard);
  output.push_back('\n');
  output.append("#define ");
  output.append(guard);
  output.push_back('\n');
  if (!body_.empty()) {
    output.push_back('\n');
    output.append(body_);
  }
  output.push_back('\n');
  output.append("#endif  // ");
  output.append(guard);
  output.push_back('\n');
  return output;
}

int AsmHeader::Output(const char* filename, std::string_view include_name) {
  const std::string output = AsmHeader::Output(include_name);

  {
    std::ifstream existing(filename, std::ios::binary);
    if (existing) {
      const std::string current((std::istreambuf_iterator<char>(existing)),
                                std::istreambuf_iterator<char>());
      if (current == output) {
        return 0;
      }
    }
  }

  std::ofstream file(filename, std::ios::binary | std::ios::trunc);
  if (!file.is_open()) {
    return errno == 0 ? EIO : errno;
  }

  file.write(output.data(), static_cast<std::streamsize>(output.size()));
  if (!file.good()) {
    return errno == 0 ? EIO : errno;
  }

  return 0;
}

int AsmHeader::Main(int argc, char** argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s <output> <include-name>\n",
                 argc > 0 ? argv[0] : "hwreg-asm-header");
    return 1;
  }

  const int error = Output(argv[1], argv[2]);
  if (error != 0) {
    std::fprintf(stderr, "%s: %s\n", argv[1], std::strerror(error));
    return 1;
  }
  return 0;
}

void AsmHeader::FieldMacro(std::string_view prefix, const char* name, uint32_t bit_high_incl,
                           uint32_t bit_low) {
  const std::string field = std::string(prefix) + ToMacroIdentifier(name);
  if (bit_high_incl == bit_low) {
    Macro(field, uint64_t{1} << bit_low);
    return;
  }

  const uint32_t width = bit_high_incl - bit_low + 1;
  const uint64_t value_mask = MaskForWidth(width);
  const uint64_t field_mask = value_mask << bit_low;

  Macro(field + "_SHIFT", bit_low);
  Macro(field + "_MASK", field_mask);
  Macro(field + "_FIELD(value)", "(((value) & " + HexLiteral(value_mask) + ") << " +
                                   std::to_string(bit_low) + ")");
}

void AsmHeader::RegisterMacros(std::string_view prefix, uint64_t rsvdz, uint64_t known,
                               uint64_t unknown) {
  const std::string base(prefix);
  Macro(base + "MASK", known);
  Macro(base + "RSVDZ", rsvdz);
  Macro(base + "UNKNOWN", unknown);
}

}  // namespace hwreg