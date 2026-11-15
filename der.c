#include <assert.h>
#include "der.h"
#include "integer.h"

enum {
  TAG_NUMBER_MASK=0x1F,
  TAG_CLASS_SHIFT=6,
  TAG_CONSTRUCTED_MASK=0x20,
  TAG_LENGTH_VALUE_MASK=0x7F,
  BASE128_BITS_COUNT=7,
  BASE128_VALUE_MASK=0x7F,
  BASE128_CONTINUATION_BIT=0x80,
  TAG_LENGTH_LONG_FORM_BIT=0x80,
  OCTET_BITS_COUNT=8,
  SHORT_FORM_MAX_LENGTH=128,
  MIN_HIGH_TAG_NUMBER=0x1F,
  DER_LENGTH_INITIAL_OCTETS=1,
  DER_TAG_INITIAL_OCTETS=1,
  DER_NODE_INITIAL_CAPACITY=16,
};

static unsigned count_bits(uint32_t n) 
{
  if(n==0)
    return 1;
  unsigned count=0;
  while(n>0){
    n=n>>1;
    count++;
  }
  return count;
}

static unsigned min_bitfields(uint32_t n,uint8_t bit_width)
{
  unsigned bit_count=count_bits(n);
  return (bit_count+bit_width-1)/bit_width;
}

static decode_der_element_status_t der_element_decode_tag(const uint8_t *buf,size_t size,tag_t *out)
{
  assert(buf!=NULL);
  assert(out!=NULL);
  assert(size!=0);
  uint8_t tag_byte = buf[0];
  uint8_t tag_class=tag_byte >> TAG_CLASS_SHIFT;
  uint8_t tag_type=(tag_byte & TAG_CONSTRUCTED_MASK)!=0;
  uint32_t tag_number=tag_byte & TAG_NUMBER_MASK;
  size_t encoded_tag_size=DER_TAG_INITIAL_OCTETS;
  bool has_high_tag_number=tag_number >= MIN_HIGH_TAG_NUMBER;
  if (has_high_tag_number) {
    tag_number=0;
    uint8_t octet;
    do {
      if(encoded_tag_size>=size)
        return DECODE_DER_ELEMENT_TRUNCATED;
      octet=buf[encoded_tag_size];
      if(tag_number>(UINT32_MAX >> BASE128_BITS_COUNT))
        return DECODE_DER_ELEMENT_INVALID_ENCODING;
      tag_number=(tag_number << BASE128_BITS_COUNT) | (octet & BASE128_VALUE_MASK);
      encoded_tag_size++;
    }while((octet & BASE128_CONTINUATION_BIT)!=0);
  }
  if(encoded_tag_size>=size)
    return DECODE_DER_ELEMENT_TRUNCATED;
  if(tag_number<MIN_HIGH_TAG_NUMBER && encoded_tag_size>1)
    return DECODE_DER_ELEMENT_INVALID_ENCODING;
  if(encoded_tag_size-1>min_bitfields(tag_number,BASE128_BITS_COUNT))
    return DECODE_DER_ELEMENT_INVALID_ENCODING;

  out->number=tag_number;
  out->class=tag_class;
  out->type=tag_type;
  out->encoded_size=encoded_tag_size;
  return DECODE_DER_ELEMENT_STATUS_OK;
}

static decode_der_element_status_t der_element_decode_length(const uint8_t *buf,size_t size,tag_t *tag, size_t *length_octet_count, uint32_t *value_len)
{
  assert(buf!=NULL);
  assert(tag!=NULL);
  assert(length_octet_count!=NULL);
  assert(value_len!=NULL);
  uint8_t len_octet=buf[tag->encoded_size];
  bool is_long_form_len=(len_octet & TAG_LENGTH_LONG_FORM_BIT);
  uint32_t decoded_value_len = 0;
  size_t encoded_length_size=0;
  if(is_long_form_len) {
    encoded_length_size= len_octet & TAG_LENGTH_VALUE_MASK;
    if(encoded_length_size>sizeof(decoded_value_len)) 
      return DECODE_DER_ELEMENT_INVALID_ENCODING;
    if(encoded_length_size==0)
      return DECODE_DER_ELEMENT_INVALID_ENCODING;
    size_t length_offset=tag->encoded_size+DER_LENGTH_INITIAL_OCTETS;
    if(encoded_length_size>size-length_offset)
      return DECODE_DER_ELEMENT_TRUNCATED;
    for (size_t i=0;i<encoded_length_size; i++) {
      decoded_value_len |= (uint32_t)buf[length_offset+i] << (OCTET_BITS_COUNT*(encoded_length_size-i-1));
    }
    if(decoded_value_len<SHORT_FORM_MAX_LENGTH)
      return DECODE_DER_ELEMENT_INVALID_ENCODING;
    if(encoded_length_size>min_bitfields(decoded_value_len,OCTET_BITS_COUNT))
      return DECODE_DER_ELEMENT_INVALID_ENCODING;
  }else {
    decoded_value_len= len_octet & TAG_LENGTH_VALUE_MASK;
  }
  *length_octet_count=encoded_length_size;
  *value_len=decoded_value_len;
  return DECODE_DER_ELEMENT_STATUS_OK;
}

decode_der_element_status_t der_element_decode(const uint8_t *buf,size_t size,der_element_t *out)
{
  if(buf==NULL ||out==NULL)
    return DECODE_DER_ELEMENT_INVALID_ARG;
  if(size<=1)
    return DECODE_DER_ELEMENT_TRUNCATED;
  tag_t tag={0};
  decode_der_element_status_t tag_decode_status=der_element_decode_tag(buf,size,&tag);
  if(tag_decode_status!=DECODE_DER_ELEMENT_STATUS_OK)
    return tag_decode_status;
  size_t encoded_length_size;
  uint32_t value_len;
  decode_der_element_status_t length_decode_status=der_element_decode_length(buf,size,&tag,&encoded_length_size,&value_len);
  if(length_decode_status!=DECODE_DER_ELEMENT_STATUS_OK)
    return length_decode_status;
  size_t length_offset=tag.encoded_size+DER_LENGTH_INITIAL_OCTETS;
  size_t header_len=length_offset+encoded_length_size;
  if(value_len>size-header_len)
    return DECODE_DER_ELEMENT_TRUNCATED;
  out->tag=tag;
  out->value_len=value_len;
  out->value=out->value_len>0?buf+header_len:NULL;
  out->header_len=header_len;
  out->encoded_size=header_len+value_len;
  out->start=buf;
  return DECODE_DER_ELEMENT_STATUS_OK;
}

static der_element_node_t* der_element_node_create(der_element_t element)
{
  der_element_node_t *node=calloc(1,sizeof(*node));
  if(node==NULL)
    return NULL;
  node->element=element;
  return node;
}

static bool der_element_node_add_child(der_element_node_t *parent, der_element_node_t *child)
{
  if(parent->count>=parent->capacity){
    size_t new_capacity=0;
    if(parent->capacity==0)
      new_capacity=DER_NODE_INITIAL_CAPACITY;
    else {
      if(parent->capacity<=(SIZE_MAX/2))
        new_capacity=parent->capacity*2;
      else
        return false;
    }
    der_element_node_t **tmp=NULL;
    if(new_capacity<=(SIZE_MAX/sizeof(*parent->children)))
      tmp=realloc(parent->children,sizeof(*parent->children)*new_capacity);
    else
      return false;
    if(tmp==NULL)
      return false;
    parent->children=tmp;
    parent->capacity=new_capacity;
  }
  parent->children[parent->count]=child;
  parent->count++;
  return true;
}

//TODO:recursive function should have a max depth, otherwise it can be exploited 
der_element_node_t* der_element_tree_build(der_element_t element)
{
  der_element_node_t* node=der_element_node_create(element);
  if(node==NULL)
    return NULL;
  if (element.tag.type == PRIMITIVE) 
    return node;
  else if (element.tag.type == CONSTRUCTED) {
    const uint8_t *value_ptr = element.value;
    size_t remaining= element.value_len;
    while(remaining>0) {
      der_element_t child = {0};
      decode_der_element_status_t decode_result= der_element_decode(value_ptr,remaining,&child);
      if(decode_result!=DECODE_DER_ELEMENT_STATUS_OK) {
        der_element_tree_destroy(node);
        return NULL;
      }
      der_element_node_t* child_node=der_element_tree_build(child);
      if(child_node==NULL) {
        der_element_tree_destroy(node);
        return NULL;
      }
      bool add_child_res=der_element_node_add_child(node,child_node);
      if(add_child_res==false){
        der_element_tree_destroy(child_node);
        der_element_tree_destroy(node);
        return NULL;
      }
      value_ptr+=child_node->element.encoded_size;
      remaining-=(child_node->element.encoded_size);
    }
    return node;
  } else{
    der_element_tree_destroy(node);
    return NULL;
  }
}

void der_element_tree_destroy(der_element_node_t *node)
{
  if(node==NULL)
    return;
  for(size_t i=0; i<node->count; i++){
    der_element_tree_destroy(node->children[i]);
  }
  free(node->children);
  free(node);
}
