#ifndef OID_H
#define OID_H

typedef struct oid_t {
	uint8_t *buffer;
	size_t length;
	size_t arc_count;
	uint64_t *arcs;
} oid_t;

oid_t *oid_create(uint8_t *buf,size_t len);
char *oid_to_str(oid_t *oid);

#endif
