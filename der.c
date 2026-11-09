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

void print_data(const uint8_t *data,size_t len)
{
  for (size_t i=0;i<len; i++) {
    printf("%02X,",data[i]);
  }
  printf("\n");
}

void print_der_element_node(der_element_node_t *node,int indent) 
{
  const char *tag_number_str=tag_number_t_toString(node->element.tag.number);
  char str[20]={0};
  if(node->element.tag.class==CONTEXT_SPECIFIC){
    sprintf(str,"[%d]",node->element.tag.number);
    tag_number_str=str;
  } 
  const char *type_str=type_t_toString(node->element.tag.type);
  printf("%*s %s(%s,len=%zu):",indent,"",tag_number_str,type_str,node->element.value_len);
  if (node->count <= 0) {
    for(size_t i=0; i<node->element.value_len; i++) {
      printf("%02X,",*(node->element.value+i));
    }
  } else {
    for(size_t i=node->element.header_len+2; i>0; i--) {
      printf("%02X,",*(node->element.value-i));
    }
  }
  printf("\n");
  for(size_t i=0; i<node->count; i++){
    print_der_element_node(node->children[i],indent+1);
  }
}

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
  uint8_t len_octet=buf[tag->encoded_size];
  bool is_long_form_len=(len_octet & TAG_LENGTH_LONG_FORM_BIT);
  uint32_t decoded_value_len = 0;
  size_t encoded_length_size=0;
  if(is_long_form_len) {
    encoded_length_size= len_octet & TAG_LENGTH_VALUE_MASK;
    //since value_len is uint32_t, it can't hold more than size of uint32_t
    if(encoded_length_size>sizeof(decoded_value_len)) 
      return DECODE_DER_ELEMENT_INVALID_ENCODING;
    //indefinite length isn't allowed in DER in the long form
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
  decode_der_element_status_t tag_parse_status=der_element_decode_tag(buf,size,&tag);
  if(tag_parse_status!=DECODE_DER_ELEMENT_STATUS_OK)
    return tag_parse_status;
  size_t encoded_length_size;
  uint32_t value_len;
  decode_der_element_status_t length_parse_status=der_element_decode_length(buf,size,&tag,&encoded_length_size,&value_len);
  if(length_parse_status!=DECODE_DER_ELEMENT_STATUS_OK)
    return length_parse_status;
  size_t length_offset=tag.encoded_size+DER_LENGTH_INITIAL_OCTETS;
  size_t header_len=length_offset+encoded_length_size;
  if(value_len>size-header_len)
    return DECODE_DER_ELEMENT_TRUNCATED;
  out->tag=tag;
  out->value_len=value_len;
  out->value=out->value_len>0?buf+header_len:NULL;
  out->header_len=header_len;
  out->start=buf;
  return DECODE_DER_ELEMENT_STATUS_OK;
}

static der_element_node_t* der_element_node_create(der_element_t element)
{
  der_element_node_t *node=calloc(1,sizeof(*node));
  if(node==NULL)
    return NULL;
  node->element=element;
  node->capacity=0;
  node->count=0;
  return node;
}

static bool der_element_node_add_child(der_element_node_t *parent, der_element_node_t *child)
{
  if(parent->count>=parent->capacity){
    size_t new_capacity=0;
    if(parent->capacity==0)
      new_capacity=DER_NODE_INITIAL_CAPACITY;
    else {
      if(parent->capacity<(SIZE_MAX/2))
        new_capacity=parent->capacity*2;
      else
        return false;
    }
    der_element_node_t **tmp=NULL;
    if(new_capacity<(SIZE_MAX/sizeof(der_element_node_t*)))
      tmp=realloc(parent->children,sizeof(der_element_node_t*)*new_capacity);
    else
      return false;
    if(tmp==NULL)
      return false;
    parent->children=tmp;
    parent->capacity=new_capacity;
  }
  size_t cnt=parent->count;
  parent->children[cnt]=child;
  parent->count+=1;
  return true;
}


//TODO:check child length cannot be greater than parent length
der_element_node_t* der_element_tree_build(der_element_t element)
{
  der_element_node_t* node=der_element_node_create(element);
  if(node==NULL)
    return NULL;
  size_t len=element.value_len;
  const uint8_t *value_ptr = element.value;
  if (element.tag.type == CONSTRUCTED) {
    while(value_ptr!=NULL && value_ptr < element.value+element.value_len-1) {
      der_element_t child = {0};
      decode_der_element_status_t parse_result= der_element_decode(value_ptr,len,&child);
      if(parse_result!=DECODE_DER_ELEMENT_STATUS_OK) {
        return NULL;
      }
      der_element_node_t* childNode=der_element_tree_build(child);
      if(childNode==NULL) {
        return NULL;
      }
      bool add_child_res=der_element_node_add_child(node,childNode);
      if(add_child_res==false)
        return NULL;
      if(childNode->element.value==NULL && childNode->element.value_len==0)
        value_ptr=value_ptr+2;
      else
        value_ptr=childNode->element.value+childNode->element.value_len;
    }
  } 
  return node;
}
