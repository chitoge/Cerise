// Custom limits.h for kernel bitmap compilation: provides integer-literal
// MAX constants that are valid in preprocessor #if arithmetic.
#pragma once

#define CHAR_BIT   8
#define SCHAR_MIN  (-128)
#define SCHAR_MAX  127
#define UCHAR_MAX  0xFFU
#define CHAR_MIN   0
#define CHAR_MAX   0xFFU
#define SHRT_MIN   (-32768)
#define SHRT_MAX   32767
#define USHRT_MAX  0xFFFFU
#define INT_MIN    (-2147483648)
#define INT_MAX    2147483647
#define UINT_MAX   0xFFFFFFFFU
#define LONG_MIN   (-9223372036854775808L)
#define LONG_MAX   9223372036854775807L
#define ULONG_MAX  0xFFFFFFFFFFFFFFFFUL
#define LLONG_MIN  (-9223372036854775808LL)
#define LLONG_MAX  9223372036854775807LL
#define ULLONG_MAX 0xFFFFFFFFFFFFFFFFULL
#define SIZE_MAX   __SIZE_MAX__
