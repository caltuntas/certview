#ifndef X509_H
#define X509_H
#include <stdbool.h>
#include "der.h"
#include "bigint.h"
#include "oid.h"

#define REFERENCE_TYPE 777

typedef enum encoding_type_t {
  NONE,
	EXPLICIT,
	IMPLICIT
} encoding_type_t;

typedef struct {
  uint8_t unused_bits;
  uint8_t *data;
  size_t length;
  size_t bit_length;
} bit_string_t;

typedef struct field_t {
	char *name;
	char *reference_type;
	int value_type;
	int element_type;
	bool required;
  struct field_t *parent;
	struct field_t **children;
	size_t count;
  encoding_type_t encoding_type;
  bool has_default;
  int tag_number;
  int tag_class;
  int pc;
} field_t;

typedef struct field_value_t {
  field_t *field;
  tlv_node_t *tlv;
  size_t count;
  struct field_value_t **children;
  bool decoded;
  union {
    bigint_t *bigint; 
    oid_t *oid; 
    bit_string_t *bitstring; 
  } value;
} field_value_t;

void print_field(field_t *field,int indent);
void print_field_value(field_value_t *value,int indent);
void add_field(field_t *parent, field_t *child);
bool validate_schema(field_t *parent,tlv_node_t *tlv,field_value_t **out);
field_t* create_x509_definition();
void print_debug(bool valid, uint8_t *data,size_t data_len,tlv_node_t *node,field_t *field, field_value_t *value);
void decode(field_value_t *value);
bit_string_t *bit_string_create(uint8_t *buf,size_t len);
char *bit_string_to_str(bit_string_t *bitstring);

#endif
