#include <stdarg.h>

extern "C" [[noreturn]] void assert_fail(const char* file, int line, const char* expression) {
  __builtin_trap();
}

extern "C" [[noreturn]] void assert_fail_msg(const char* file, int line, const char* expression,
                                             const char* fmt, ...) {
  __builtin_trap();
}
