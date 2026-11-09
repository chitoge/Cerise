// Temporary zbi-format compatibility shim for the curated workspace snapshot.
// This preserves the narrow platform ID surface currently needed by
// zircon/kernel/phys/include/phys/handoff.h.

#ifndef LIB_ZBI_FORMAT_BOARD_H_
#define LIB_ZBI_FORMAT_BOARD_H_

#include <stdint.h>

#define ZBI_BOARD_NAME_LEN 32

typedef struct {
  uint32_t vid;
  uint32_t pid;
  char board_name[ZBI_BOARD_NAME_LEN];
} zbi_platform_id_t;

#endif  // LIB_ZBI_FORMAT_BOARD_H_