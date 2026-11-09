#ifndef ZIRCON_ASSERT_H_
#define ZIRCON_ASSERT_H_

#if defined(__STDC_HOSTED__) && __STDC_HOSTED__
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#define ZX_INTERNAL_ASSERT_FAILURE(format, ...) \
    do {                                        \
        fprintf(stderr, format "\n", ##__VA_ARGS__); \
        abort();                                \
    } while (0)
#else
#ifdef __cplusplus
namespace zircon_assert_internal {
template <typename... Args>
inline void ConsumeFailureArgs(Args&&...) {}
}  // namespace zircon_assert_internal

#define ZX_INTERNAL_ASSERT_FAILURE(format, ...)                             \
    do {                                                                    \
        ::zircon_assert_internal::ConsumeFailureArgs(format, ##__VA_ARGS__); \
        __builtin_trap();                                                   \
    } while (0)
#else
#define ZX_INTERNAL_ASSERT_FAILURE(...) __builtin_trap()
#endif
#endif

#define ZX_DEBUG_ASSERT_IMPLEMENTED 1

#ifdef __cplusplus

#define ZX_ASSERT(condition)                                                  \
    do {                                                                      \
        [&] {                                                                 \
            if (condition) {                                                  \
                return;                                                       \
            } else {                                                          \
                ZX_INTERNAL_ASSERT_FAILURE("ZX_ASSERT(%s) failed", #condition); \
            }                                                                 \
        }();                                                                  \
    } while (0)

#define ZX_DEBUG_ASSERT(condition) ZX_ASSERT(condition)
#define ZX_DEBUG_ASSERT_COND(condition) ZX_DEBUG_ASSERT(condition)
#define ZX_ASSERT_COND(condition) ZX_DEBUG_ASSERT(condition)

#define ZX_ASSERT_MSG(condition, format, ...)                  \
    do {                                                       \
        [&] {                                                  \
            if (condition) {                                   \
                return;                                        \
            } else {                                           \
                ZX_INTERNAL_ASSERT_FAILURE(format, ##__VA_ARGS__); \
            }                                                  \
        }();                                                   \
    } while (0)

#else

#if defined(__STDC_HOSTED__) && __STDC_HOSTED__
#define ZX_ASSERT(condition) assert(condition)
#else
#define ZX_ASSERT(condition)             \
    do {                                \
        if (!(condition)) {             \
            ZX_INTERNAL_ASSERT_FAILURE(); \
        }                               \
    } while (0)
#endif

#define ZX_DEBUG_ASSERT(condition) ZX_ASSERT(condition)
#define ZX_DEBUG_ASSERT_COND(condition) ZX_DEBUG_ASSERT(condition)
#define ZX_ASSERT_COND(condition) ZX_DEBUG_ASSERT(condition)

#define ZX_ASSERT_MSG(condition, format, ...)       \
    do {                                            \
        if (!(condition)) {                         \
            ZX_INTERNAL_ASSERT_FAILURE(format, ##__VA_ARGS__); \
        }                                           \
    } while (0)

#endif

#define ZX_DEBUG_ASSERT_MSG(condition, format, ...) \
    ZX_ASSERT_MSG(condition, format, ##__VA_ARGS__)

#define ZX_PANIC(format, ...)                       \
    do {                                            \
        ZX_INTERNAL_ASSERT_FAILURE(format, ##__VA_ARGS__); \
    } while (0)

#endif  // ZIRCON_ASSERT_H_