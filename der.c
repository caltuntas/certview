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
};

void print_data(const uint8_t *data,size_t len)
{
  for (size_t i=0;i<len; i++) {
    printf("%02X,",data[i]);
  }
  printf("\n");
}

void print_tlv_node(tlv_node_t *node,int indent) 
{
  const char *tag_number_str=tag_number_t_toString(node->tlv.tag.number);
  char str[20]={0};
  if(node->tlv.tag.class==CONTEXT_SPECIFIC){
    sprintf(str,"[%d]",node->tlv.tag.number);
    tag_number_str=str;
  } 
  const char *type_str=type_t_toString(node->tlv.tag.type);
  printf("%*s %s(%s,len=%zu):",indent,"",tag_number_str,type_str,node->tlv.value_len);
  if (node->count <= 0) {
    for(size_t i=0; i<node->tlv.value_len; i++) {
      printf("%02X,",*(node->tlv.value+i));
    }
  } else {
    for(size_t i=node->tlv.header_len+2; i>0; i--) {
      printf("%02X,",*(node->tlv.value-i));
    }
  }
  printf("\n");
  for(size_t i=0; i<node->count; i++){
    print_tlv_node(node->children[i],indent+1);
  }
}

void print_node_values(tlv_node_t *node,int indent) 
{
  const char *tag_number_str=tag_number_t_toString(node->tlv.tag.number);
  char str[20]={0};
  if(node->tlv.tag.class==CONTEXT_SPECIFIC){
    sprintf(str,"[%d]",node->tlv.tag.number);
    tag_number_str=str;
  } 
  const char *type_str=type_t_toString(node->tlv.tag.type);
  printf("%*s %s(%s,len=%zu):",indent,"",tag_number_str,type_str,node->tlv.value_len);
  if (node->count <= 0) {
    for(size_t i=0; i<node->tlv.value_len; i++) {
      printf("%02X,",*(node->tlv.value+i));
    }
  } else {
    for(size_t i=node->tlv.header_len+2; i>0; i--) {
      printf("%02X,",*(node->tlv.value-i));
    }
  }
  printf("\n");
  for(size_t i=0; i<node->count; i++){
    print_node_values(node->children[i],indent+1);
  }
}

unsigned count_bits(uint32_t n) 
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

unsigned min_bitfields(uint32_t n,uint8_t bit_width)
{
  unsigned bit_count=count_bits(n);
  return (bit_count+bit_width-1)/bit_width;
}

parse_tlv_status_t der_decode_tag(const uint8_t *buf,size_t size,tag_t *out)
{
  uint8_t tag_byte = buf[0];
  out->class = tag_byte >> TAG_CLASS_SHIFT;
  out->type=(tag_byte & TAG_CONSTRUCTED_MASK)!=0;
  uint32_t tag_number=tag_byte & TAG_NUMBER_MASK;
  out->encoded_size=1;
  size_t required_header_size;
  bool has_high_tag_number=(tag_number >= MIN_HIGH_TAG_NUMBER)!=0;
  if (has_high_tag_number) {
    tag_number=0;
    uint8_t octet;
    do {
      octet=buf[out->encoded_size];
      if(tag_number>(UINT32_MAX >> BASE128_BITS_COUNT))
        return PARSE_TLV_INVALID_ENCODING;
      tag_number=(tag_number << BASE128_BITS_COUNT) | (octet & BASE128_VALUE_MASK);
      out->encoded_size++;
      if(!integer_add_sizet_safe(out->encoded_size,1,&required_header_size)){
        return PARSE_TLV_INVALID_ENCODING;
      }
      if(size < required_header_size)
        return PARSE_TLV_TRUNCATED;
    }while((octet & BASE128_CONTINUATION_BIT)!=0);
  }
  if(!integer_add_sizet_safe(out->encoded_size,1,&required_header_size)){
    return PARSE_TLV_INVALID_ENCODING;
  }
  if(size < required_header_size)
    return PARSE_TLV_TRUNCATED;
  if(tag_number<MIN_HIGH_TAG_NUMBER && out->encoded_size>1)
    return PARSE_TLV_INVALID_ENCODING;
  if(out->encoded_size-1>min_bitfields(tag_number,BASE128_BITS_COUNT))
    return PARSE_TLV_INVALID_ENCODING;

  out->number=tag_number;
  return PARSE_TLV_OK;
}

parse_tlv_status_t der_decode_length(const uint8_t *buf,size_t size,tag_t *tag, size_t *length_octet_count, uint32_t *value_len)
{
  uint8_t len=buf[tag->encoded_size];
  bool is_long_form_len=(len & TAG_LENGTH_LONG_FORM_BIT);
  if(is_long_form_len) {
    *length_octet_count = len & TAG_LENGTH_VALUE_MASK;
    //since value_len is uint32_t, it can't hold more than size of uint32_t
    if(*length_octet_count>sizeof(uint32_t)) 
      return PARSE_TLV_INVALID_ENCODING;
    size_t header_size;
    if(!integer_add_sizet_safe(*length_octet_count,tag->encoded_size,&header_size))
      return PARSE_TLV_INVALID_ENCODING;
    if(!integer_add_sizet_safe(header_size,1,&header_size))
      return PARSE_TLV_INVALID_ENCODING;
    if(size<header_size)
      return PARSE_TLV_TRUNCATED;
    size_t length_offset;
    if(!integer_add_sizet_safe(tag->encoded_size,1,&length_offset)){
      return PARSE_TLV_INVALID_ENCODING;
    }
    for (size_t i=0;i<*length_octet_count; i++) {
      size_t current_offset;
      if(!integer_add_sizet_safe(length_offset,i,&current_offset)){
        return PARSE_TLV_INVALID_ENCODING;
      }
      *value_len |= (uint32_t)buf[current_offset] << (OCTET_BITS_COUNT*(*length_octet_count-i-1));
    }
    if(*value_len<SHORT_FORM_MAX_LENGTH)
      return PARSE_TLV_INVALID_ENCODING;
    if(*length_octet_count>min_bitfields(*value_len,OCTET_BITS_COUNT))
      return PARSE_TLV_INVALID_ENCODING;
  }else {
    *value_len = len & TAG_LENGTH_VALUE_MASK;
  }
  return PARSE_TLV_OK;
}

parse_tlv_status_t der_decode_element(const uint8_t *buf,size_t size,der_element_t *out)
{
  if(buf==NULL ||out==NULL){
    return PARSE_TLV_INVALID_ARG;
  }
  if(size<=1) {
    return PARSE_TLV_TRUNCATED;
  }
  tag_t tag={0};
  parse_tlv_status_t tag_parse_status=der_decode_tag(buf,size,&tag);
  if(tag_parse_status!=PARSE_TLV_OK)
    return tag_parse_status;
  size_t length_octet_count=0;
  uint32_t value_len=0;
  parse_tlv_status_t length_parse_status=der_decode_length(buf,size,&tag,&length_octet_count,&value_len);
  if(length_parse_status!=PARSE_TLV_OK)
    return length_parse_status;
  size_t value_index;
  size_t header_len;
  size_t required_size;
  if(!integer_add_sizet_safe(tag.encoded_size,1,&value_index))
    return PARSE_TLV_INVALID_ENCODING;
  if(!integer_add_sizet_safe(length_octet_count,value_index,&header_len))
    return PARSE_TLV_INVALID_ENCODING;
  if(!integer_add_sizet_safe(header_len,value_len,&required_size))
    return PARSE_TLV_INVALID_ENCODING;
  if(size<required_size) 
    return PARSE_TLV_TRUNCATED;
  out->tag=tag;
  out->value_len=value_len;
  if(out->value_len>0){
    out->value=buf+header_len;
    out->header_len=header_len;
  }
  else {
    out->value=NULL;
    out->header_len=value_index;
  }
  out->start=buf;
  return PARSE_TLV_OK;
}

tlv_node_t* create_node(der_element_t t)
{
  tlv_node_t *node=calloc(1,sizeof(*node));
  node->tlv=t;
  return node;
}

void add_node(tlv_node_t *parent, tlv_node_t *child)
{
  size_t cnt=parent->count;
  parent->children=realloc(parent->children,sizeof(tlv_node_t*)*(parent->count+1));
  parent->children[cnt]=child;
  parent->count+=1;
}


//TODO:check child length cannot be greater than parent length
tlv_node_t* build_tlv(der_element_t tlv)
{
  tlv_node_t* node=create_node(tlv);
  size_t len=tlv.value_len;
  const uint8_t *value_ptr = tlv.value;
  if (tlv.tag.type == CONSTRUCTED) {
    size_t count=node->count;
    while(value_ptr!=NULL && value_ptr < tlv.value+tlv.value_len-1) {
      der_element_t child = {0};
      parse_tlv_status_t parse_result= der_decode_element(value_ptr,len,&child);
      if(parse_result!=PARSE_TLV_OK) {
        return NULL;
      }
      tlv_node_t* childNode=build_tlv(child);
      if(childNode==NULL) {
        return NULL;
      }
      add_node(node,childNode);
      if(childNode->tlv.value==NULL && childNode->tlv.value_len==0)
        value_ptr=value_ptr+2;
      else
        value_ptr=node->children[count]->tlv.value+node->children[count]->tlv.value_len;
      //len=child.value_len;
      count++;
      node->count=count;
    }
  } else if (tlv.tag.type == PRIMITIVE) {
    node->tlv.tag.class = tlv.tag.class;
    node->tlv.tag.number = tlv.tag.number;
    node->tlv.tag.type = tlv.tag.type;
    node->tlv.value_len= tlv.value_len;
    node->tlv.value= tlv.value;
  }
  return node;
}
