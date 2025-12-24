#ifndef DER_H
#define DER_H

#include <stdint.h>
#include <stdlib.h>

#define ENUM_ENTRY(name,value) name = value,
#define ENUM_DECLARE(MACRO_DEFINITION,enum_name)\
  typedef enum\
  {\
    MACRO_DEFINITION(ENUM_ENTRY)\
  }\
  enum_name;

#define ENUM_TOSTRING_CASE(name,value) case name: return #name;
#define ENUM_DEFINE_TO_STRING(MACRO_DEFINITION,enum_name)\
  static inline const char* enum_name##_toString(enum_name value)\
  {\
    switch(value)\
    {\
      MACRO_DEFINITION(ENUM_TOSTRING_CASE)\
      default:\
        return 0;\
    }\
  }\


//https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
//https://luca.ntop.org/Teaching/Appunti/asn1.html
#define ENUM_class(_)\
  _(UNIVERSAL,0)\
  _(APPLICATION,1)\
  _(CONTEXT_SPECIFIC,2)\
  _(PRIVATE,3)

ENUM_DECLARE(ENUM_class, class_t)
ENUM_DEFINE_TO_STRING(ENUM_class, class_t)

#define ENUM_type(_)\
  _(PRIMITIVE,0)\
  _(CONSTRUCTED,1)

ENUM_DECLARE(ENUM_type, type_t)
ENUM_DEFINE_TO_STRING(ENUM_type, type_t)

#define ENUM_tag_number(_)\
  _(BOOLEAN,1 )\
  _(INTEGER,2 )\
  _(BIT_STRING,3  )\
  _(OCTET_STRING,4  )\
  _(NULL_VALUE,5  )\
  _(OBJECT_IDENTIFIER,6 )\
  _(UTF8String,12 )\
  _(SEQUENCE,16 )\
  _(SET,17 )\
  _(PrintableString,19  )\
  _(IA5String,22  )\
  _(UTCTime,23  )\
  _(GeneralizedTime,24)

ENUM_DECLARE(ENUM_tag_number, tag_number_t)
ENUM_DEFINE_TO_STRING(ENUM_tag_number, tag_number_t)

typedef enum {
  ANY,
  CHOICE
} semantic_type_t;

typedef struct {
  class_t class;
  type_t type;
  tag_number_t number;
} tag_t;

typedef struct {
  tag_t tag;
  uint32_t len;
  uint32_t len_meta;
  uint8_t *value;
} tlv_t;


typedef struct tlv_node_t {
  tlv_t tlv;
  struct tlv_node_t* children;
  size_t count;
} tlv_node_t;

tlv_t parse_tlv(uint8_t *buf,size_t size);
tlv_node_t* build_tlv(tlv_t tlv);

#endif
