#ifndef LIB_ZIRCON_INTERNAL_MACROS_H_
#define LIB_ZIRCON_INTERNAL_MACROS_H_

#include <fbl/macros.h>

#ifdef __cplusplus
#include <ktl/source_location.h>
#endif

#if !defined(__ASSEMBLER__) && !defined(SOURCE_TAG)
#ifdef __cplusplus
#define SOURCE_TAG ::ktl::source_location::current().function_name()
#else
#define SOURCE_TAG __func__
#endif
#endif

#endif  // LIB_ZIRCON_INTERNAL_MACROS_H_