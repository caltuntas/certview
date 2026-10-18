#include "der.h"

void print_data(const uint8_t *data,size_t len)
{
  for (int i=0;i<len; i++) {
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
  const char *class_str=class_t_toString(node->tlv.tag.class);
  printf("%*s %s(%s,len=%d):",indent,"",tag_number_str,type_str,node->tlv.value_len);
  if (node->count <= 0) {
    for(int i=0; i<node->tlv.value_len; i++) {
      printf("%02X,",*(node->tlv.value+i));
    }
  } else {
    for(int i=node->tlv.header_len+2; i>0; i--) {
      printf("%02X,",*(node->tlv.value-i));
    }
  }
  printf("\n");
  for(int i=0; i<node->count; i++){
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
  const char *class_str=class_t_toString(node->tlv.tag.class);
  printf("%*s %s(%s,len=%d):",indent,"",tag_number_str,type_str,node->tlv.value_len);
  if (node->count <= 0) {
    for(int i=0; i<node->tlv.value_len; i++) {
      printf("%02X,",*(node->tlv.value+i));
    }
  } else {
    for(int i=node->tlv.header_len+2; i>0; i--) {
      printf("%02X,",*(node->tlv.value-i));
    }
  }
  printf("\n");
  for(int i=0; i<node->count; i++){
    print_node_values(node->children[i],indent+1);
  }
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
  if(buf==NULL){
    return PARSE_TLV_INVALID_ARG;
  }

  if(buf!=NULL && size<=1) {
    return PARSE_TLV_INVALID_ARG;
  }

  uint8_t tag_byte = buf[0];
  tag_t tag={0};
  tag.class = tag_byte >> 6;
  tag.type=(tag_byte & 0b00100000)!=0;
  tag.number=tag_byte & 0x1F;

	out->tag=tag;
  uint8_t len=buf[1];
  uint8_t bytes=0;
  if(len > 128) {
    bytes = len & 0x0F;
    for (int i=0;i<bytes; i++) {
      out->value_len |= buf[2+i] << (8*(bytes-i-1));
    }
  } else {
    out->value_len =len;
  }
  if(out->value_len>0){
    out->value=buf+bytes+2;
		out->header_len=bytes+2;
	}
  else {
    out->value=NULL;
		out->header_len=2;
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
      tlv_node_t* childNode=build_tlv(child);
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
