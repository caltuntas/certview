#include "der.h"
#include "integer.h"

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

//TODO:negative integers
//TODO:check tvl length and buffer size discrepancy
//TODO:bit string parsing edge cases
//TODO:check invalid encodings for instance integer cannot be constructed 
/*
Tag Byte: 7 6 5 4 3 2 1 0
          | | |-----------|
          | |       |
          | |       +-- Tag number (low 5 bits)
          | +---------- Primitive / Constructed (bit 6)
          +------------ Class (bits 7–6)
*/
parse_tlv_status_t parse_tlv(const uint8_t *buf,size_t size,tlv_t *out)
{
  if(buf==NULL ||out==NULL){
    return PARSE_TLV_INVALID_ARG;
  }
  if(size<=1) {
    return PARSE_TLV_TRUNCATED;
  }
  uint8_t tag_byte = buf[0];
  tag_t tag={0};
  tag.class = tag_byte >> 6;
  tag.type=(tag_byte & 0b00100000)!=0;
  uint32_t tag_number=tag_byte & 0x1F;
  size_t len_index=1;
  size_t required_header_size;
  if (tag_number >= 0x1F) {
    tag_number=0;
    uint8_t octet;
    do {
      octet=buf[len_index];
      if(tag_number>(UINT32_MAX >> 7))
        return PARSE_TLV_INVALID_ENCODING;
      tag_number=(tag_number << 7);
      tag_number=tag_number | (octet & 0x7F);
      len_index++;
      if(!integer_add_sizet_safe(len_index,1,&required_header_size)){
        return PARSE_TLV_INVALID_ENCODING;
      }
      if(size < required_header_size)
        return PARSE_TLV_TRUNCATED;
    }while((octet & 0x80)!=0);
  }
  if(!integer_add_sizet_safe(len_index,1,&required_header_size)){
    return PARSE_TLV_INVALID_ENCODING;
  }
  if(size < required_header_size)
    return PARSE_TLV_TRUNCATED;
  if(tag_number<31 && len_index>1)
    return PARSE_TLV_INVALID_ENCODING;
  if(len_index-1>min_bitfields(tag_number,7))
    return PARSE_TLV_INVALID_ENCODING;

  tag.number=tag_number;

  uint8_t len=buf[len_index];
  size_t bytes=0;
  uint8_t is_long_form_len=len & (1<<7);
  uint32_t value_len=0;
  size_t required_size;
  if(is_long_form_len) {
    bytes = len & 0x7F;
    //since value_len is uint32_t, it can't hold more than size of uint32_t
    if(bytes>sizeof(uint32_t)) 
      return PARSE_TLV_INVALID_ENCODING;
    size_t value_offset;
    if(!integer_add_sizet_safe(bytes,len_index,&value_offset)){
      return PARSE_TLV_INVALID_ENCODING;
    }
    if(!integer_add_sizet_safe(value_offset,1,&value_offset)){
      return PARSE_TLV_INVALID_ENCODING;
    }
    if(size<value_offset)
      return PARSE_TLV_TRUNCATED;
    size_t length_offset;
    if(!integer_add_sizet_safe(len_index,1,&length_offset)){
      return PARSE_TLV_INVALID_ENCODING;
    }
    for (size_t i=0;i<bytes; i++) {
      size_t current_offset;
      if(!integer_add_sizet_safe(length_offset,i,&current_offset)){
        return PARSE_TLV_INVALID_ENCODING;
      }
      value_len |= (uint32_t)buf[current_offset] << (8*(bytes-i-1));
    }
    if(!integer_add_sizet_safe(value_len,value_offset,&required_size)){
      return PARSE_TLV_INVALID_ENCODING;
    }
    if(size<required_size) 
      return PARSE_TLV_TRUNCATED;
    //DER requires lengths below 128 to use short-form encoding
    if(value_len<128)
      return PARSE_TLV_INVALID_ENCODING;
    if(bytes>min_bitfields(value_len,8))
      return PARSE_TLV_INVALID_ENCODING;
  }else {
    value_len = len & 0x7F;
    if(!integer_add_sizet_safe(value_len,len_index,&required_size)){
      return PARSE_TLV_INVALID_ENCODING;
    }
    if(!integer_add_sizet_safe(required_size,1,&required_size)){
      return PARSE_TLV_INVALID_ENCODING;
    }
    if(size<required_size) 
      return PARSE_TLV_TRUNCATED;
  }
  size_t value_index;
  size_t total_header_len;
  if(!integer_add_sizet_safe(len_index,1,&value_index)){
    return PARSE_TLV_INVALID_ENCODING;
  }
  if(!integer_add_sizet_safe(bytes,value_index,&total_header_len)){
    return PARSE_TLV_INVALID_ENCODING;
  }
  out->tag=tag;
  out->value_len=value_len;
  if(out->value_len>0){
    out->value=buf+total_header_len;
    out->header_len=total_header_len;
  }
  else {
    out->value=NULL;
    out->header_len=value_index;
  }
  out->start=buf;
  return PARSE_TLV_OK;
}

tlv_node_t* create_node(tlv_t t)
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
tlv_node_t* build_tlv(tlv_t tlv)
{
  tlv_node_t* node=create_node(tlv);
  size_t len=tlv.value_len;
  const uint8_t *value_ptr = tlv.value;
  if (tlv.tag.type == CONSTRUCTED) {
    size_t count=node->count;
    while(value_ptr!=NULL && value_ptr < tlv.value+tlv.value_len-1) {
      tlv_t child = {0};
      parse_tlv_status_t parse_result= parse_tlv(value_ptr,len,&child);
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
