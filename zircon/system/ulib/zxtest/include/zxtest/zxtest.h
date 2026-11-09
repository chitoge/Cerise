// zxtest → gtest compatibility shim for Cerise host tests.
// Maps <zxtest/zxtest.h> to gtest so zxtest-using tests build on host.
#ifndef ZXTEST_ZXTEST_H_
#define ZXTEST_ZXTEST_H_

#include <gtest/gtest.h>

// zxtest uses the same TEST / TEST_F / EXPECT_* / ASSERT_* as gtest.
// Extra zxtest-specific macros:
#define EXPECT_OK(expr)      EXPECT_EQ(ZX_OK, static_cast<int>(expr))
#define ASSERT_OK(expr)      ASSERT_EQ(ZX_OK, static_cast<int>(expr))
#define EXPECT_NOT_OK(expr)  EXPECT_NE(ZX_OK, static_cast<int>(expr))
#define ASSERT_NOT_OK(expr)  ASSERT_NE(ZX_OK, static_cast<int>(expr))
#define EXPECT_STATUS(s, e)  EXPECT_EQ(static_cast<int>(s), static_cast<int>(e))
#define ASSERT_STATUS(s, e)  ASSERT_EQ(static_cast<int>(s), static_cast<int>(e))
#define ZXTEST_TEST_SUITE_BEGIN(n) namespace n {
#define ZXTEST_TEST_SUITE_END()    }

// Death test macros: zxtest ASSERT_DEATH(callable, description) →
// gtest ASSERT_DEATH(statement, regex).
// We CANNOT use ASSERT_DEATH_IF_SUPPORTED here because it expands to ASSERT_DEATH(...)
// which — due to C preprocessor blue-painting — would leave a bare ASSERT_DEATH token
// that the compiler rejects. Use GTEST_DEATH_TEST_ directly to avoid the cycle.
#undef ASSERT_DEATH
#undef EXPECT_DEATH
#if GTEST_HAS_DEATH_TESTS
#define ASSERT_DEATH(fn, msg) \
  GTEST_DEATH_TEST_((fn)(), "", ::testing::kAbortOnFailure, \
                    ::testing::internal::DeathTest)
#define EXPECT_DEATH(fn, msg) \
  GTEST_DEATH_TEST_((fn)(), "", ::testing::kNonFatalFailure, \
                    ::testing::internal::DeathTest)
#else
#define ASSERT_DEATH(fn, msg)  do { (void)sizeof(#msg); } while (false)
#define EXPECT_DEATH(fn, msg)  do { (void)sizeof(#msg); } while (false)
#endif
// ASSERT_NO_DEATH: just call fn(); an actual crash fails the test process.
#define ASSERT_NO_DEATH(fn, msg) do { (fn)(); } while (false)
#define EXPECT_NO_DEATH(fn, msg) do { (fn)(); } while (false)

#endif  // ZXTEST_ZXTEST_H_
