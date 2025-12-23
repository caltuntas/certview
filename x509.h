#ifndef X509_H
#define X509_H
#include <stdbool.h>
#include "der.h"

typedef enum match_type_t {
	POSITION,
	TAG
} match_type_t;

typedef struct field_t {
	char *name;
	int asn1_type;
	bool required;
	struct field_t *children;
	size_t count;
	match_type_t match_type;
} field_t;

void add_field(field_t *parent, field_t *child);
bool validate_asn1(field_t *parent,tlv_node_t *tlv);

#endif
