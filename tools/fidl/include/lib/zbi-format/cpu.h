#ifndef LIB_ZBI_FORMAT_CPU_H_
#define LIB_ZBI_FORMAT_CPU_H_

#include <stdint.h>

typedef struct {
  uint8_t discriminant;
} zbi_topology_entity_t;

typedef struct {
  zbi_topology_entity_t entity;
  uint16_t parent_index;
} zbi_topology_node_t;

#endif  // LIB_ZBI_FORMAT_CPU_H_