// Compatibility: kernel limits.h uses cast expressions that don't work in
// preprocessor #if arithmetic. Provide literal versions for raw-bitmap.cc.
#undef UINT_MAX
#undef ULONG_MAX
#undef ULLONG_MAX
#define UINT_MAX   0xFFFFFFFFU
#define ULONG_MAX  0xFFFFFFFFFFFFFFFFUL
#define ULLONG_MAX 0xFFFFFFFFFFFFFFFFULL
#ifndef SIZE_MAX
#define SIZE_MAX __SIZE_MAX__
#endif
