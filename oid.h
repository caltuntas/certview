#ifndef OID_H
#define OID_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct oid_registry_t {
  uint64_t arc;
  char *code;
  char *name;
  struct oid_registry_t **children;
  size_t count;
} oid_registry_t;

typedef struct oid_t {
	uint8_t *buffer;
	size_t length;
	size_t arc_count;
	uint64_t *arcs;
} oid_t;

oid_t *oid_create(uint8_t *buf,size_t len);
char *oid_to_str(oid_t *oid);
char *oid_to_reg_str(oid_t *oid);

#endif
