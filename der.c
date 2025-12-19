#include "der.h"

//TODO:negative integers
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
  tlv.ptr=buf;
	return tlv;
}

tlv_node_t* build_tlv(tlv_t tlv)
{
  tlv_node_t* node=malloc(sizeof(*node));
  node->tlv=tlv;
  size_t len=tlv.len;
  uint8_t *value_ptr = tlv.value;
  if (tlv.tag.type == CONSTRUCTED) {
    size_t count=node->count;
    while(value_ptr!=NULL && value_ptr <= tlv.value+tlv.len-1) {
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
