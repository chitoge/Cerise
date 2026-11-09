#ifndef TOOLS_FIDL_INCLUDE_LIB_JITTERENTROPY_JITTERENTROPY_H_
#define TOOLS_FIDL_INCLUDE_LIB_JITTERENTROPY_JITTERENTROPY_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct rand_data {
  uint8_t unused;
};

static inline int jent_entropy_init(void) { return 1; }

static inline void jent_entropy_collector_init(struct rand_data* ec, uint8_t* mem, size_t len,
                                               uint32_t block_size, uint32_t block_count,
                                               uint32_t mem_loops, bool stir) {}

static inline uint64_t jent_lfsr_var_stat(struct rand_data* ec, uint32_t lfsr_loops,
                                          uint32_t mem_loops) {
  return 0;
}

static inline ssize_t jent_read_entropy(struct rand_data* ec, char* buf, size_t len) { return -1; }

#endif  // TOOLS_FIDL_INCLUDE_LIB_JITTERENTROPY_JITTERENTROPY_H_