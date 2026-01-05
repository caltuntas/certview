#include "der.h"

void print_tlv_node(tlv_node_t *node,int indent) 
{
  const char *tag_number_str=tag_number_t_toString(node->tlv.tag.number);
  char str[20]={0};
  if(tag_number_str==NULL) {
    if(node->tlv.tag.class ==CONTEXT_SPECIFIC && node->tlv.tag.type ==CONSTRUCTED){
      sprintf(str,"[%d] EXPLICIT",node->tlv.tag.number);
      tag_number_str=str;
    } else if(node->tlv.tag.class ==CONTEXT_SPECIFIC){
      sprintf(str,"[%d]",node->tlv.tag.number);
      tag_number_str=str;
    }
  } else {
    if(node->tlv.tag.class ==CONTEXT_SPECIFIC && node->tlv.tag.type ==CONSTRUCTED){
      sprintf(str,"[%d] EXPLICIT",node->tlv.tag.number);
      tag_number_str=str;
    } 
  }
  const char *type_str=type_t_toString(node->tlv.tag.type);
  const char *class_str=class_t_toString(node->tlv.tag.class);
  printf("%*s %s(%s,len=%d):",indent,"",tag_number_str,type_str,node->tlv.len);
  if (node->count <= 0) {
    for(int i=0; i<node->tlv.len; i++) {
      printf("%02X,",*(node->tlv.value+i));
    }
  } else {
    for(int i=node->tlv.len_meta+2; i>0; i--) {
      printf("%02X,",*(node->tlv.value-i));
    }
  }
  printf("\n");
  for(int i=0; i<node->count; i++){
    print_tlv_node(&node->children[i],indent+1);
  }
}

//TODO:negative integers
//TODO:check tvl length and buffer size discrepancy
//TODO:bit string parsing edge cases
//TODO:check invalid encodings for instance integer cannot be constructed 
tlv_t parse_tlv(uint8_t *buf,size_t size)
{
  uint8_t tag_byte = buf[0];
  tag_t tag={0};
  tag.class = tag_byte >> 6;
  tag.type=(tag_byte & 0b00100000)!=0;
  tag.number=tag_byte & 0x1F;

  tlv_t tlv={0};
	tlv.tag=tag;
  uint8_t len=buf[1];
  uint8_t bytes=0;
  if(len > 128) {
    bytes = len & 0x0F;
    for (int i=0;i<bytes; i++) {
      tlv.len |= buf[2+i] << (8*(bytes-i-1));
    }
  } else {
    tlv.len =len;
  }
  if(tlv.len>0)
    tlv.value=buf+bytes+2;
  else 
    tlv.value=NULL;
  tlv.len_meta=bytes;
	return tlv;
}

//TODO:check child length cannot be greater than parent length
tlv_node_t* build_tlv(tlv_t tlv)
{
  tlv_node_t* node=malloc(sizeof(*node));
  node->tlv=tlv;
  size_t len=tlv.len;
  uint8_t *value_ptr = tlv.value;
  if (tlv.tag.type == CONSTRUCTED) {
    size_t count=node->count;
    while(value_ptr!=NULL && value_ptr < tlv.value+tlv.len-1) {
      node->children=realloc(node->children,sizeof(tlv_node_t)*(node->count+1));
      tlv_t child = parse_tlv(value_ptr,len);
      tlv_node_t* childNode=build_tlv(child);
      node->children[count].tlv.tag.class = childNode->tlv.tag.class;
      node->children[count].tlv.tag.number = childNode->tlv.tag.number;
      node->children[count].tlv.tag.type = childNode->tlv.tag.type;
      node->children[count].tlv.len= childNode->tlv.len;
      node->children[count].tlv.len_meta= childNode->tlv.len_meta;
      node->children[count].tlv.value= childNode->tlv.value;
      node->children[count].children= childNode->children;
      node->children[count].count= childNode->count;
      if(childNode->tlv.value==NULL && childNode->tlv.len==0)
        value_ptr=value_ptr+2;
      else
        value_ptr=node->children[count].tlv.value+node->children[count].tlv.len;
      len=child.len;
      count++;
      node->count=count;
    }
  } else if (tlv.tag.type == PRIMITIVE) {
    node->tlv.tag.class = tlv.tag.class;
    node->tlv.tag.number = tlv.tag.number;
    node->tlv.tag.type = tlv.tag.type;
    node->tlv.len= tlv.len;
    node->tlv.value= tlv.value;
  }
  return node;
}
