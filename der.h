#ifndef DER_H
#define DER_H

#include <stdint.h>
#include <stdlib.h>

//https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
//https://luca.ntop.org/Teaching/Appunti/asn1.html
typedef enum {
  UNIVERSAL =0, //00
  APPLICATION=1, //01
  CONTEXT_SPECIFIC=2,//10
  PRIVATE=3//11
} class_t;


typedef enum {
  PRIMITIVE=0,
  CONSTRUCTED=1
} type_t;

typedef enum {
  INTEGER=2 ,
  BIT_STRING=3  ,
  OCTET_STRING=4  ,
  NULL_NUMBER=5  ,
  OBJECT_IDENTIFIER=6 ,
  UTF8String=12 ,
  SEQUENCE=16 ,
  SET=17 ,
  PrintableString=19  ,
  IA5String=22  ,
  UTCTime=23  ,
  GeneralizedTime=24
} tag_number_t;

typedef struct {
  class_t class;
  type_t type;
  tag_number_t number;
} tag_t;

typedef struct {
  tag_t tag;
  uint32_t len;
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
