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
  if(len > 128) {
    uint8_t bytes = len & 0x0F;
    for (int i=0;i<bytes; i++) {
      tlv.len |= buf[2+i] << (8-i*8);
    }
  } else {
    tlv.len =len;
  }
  tlv.value=buf+(size-tlv.len);
	return tlv;
}

tlv_node_t* build_tlv(tlv_t tlv)
{
  tlv_node_t* node=malloc(sizeof(*node));
  node->tlv=tlv;
  if (tlv.tag.number == SEQUENCE) {
    uint8_t *value_ptr = tlv.value;
    size_t len=tlv.len;
    size_t count=node->count;
    while(value_ptr <= tlv.value+tlv.len-1) {
      tlv_t child = parse_tlv(value_ptr,len);
      node->children=realloc(node->children,sizeof(tlv_node_t)*(node->count+1));
      node->children[count].tlv.tag.class = child.tag.class;
      node->children[count].tlv.tag.number = child.tag.number;
      node->children[count].tlv.len= child.len;
      node->children[count].tlv.value= value_ptr+child.len+1;
      value_ptr=node->children[count].tlv.value+node->children[count].tlv.len;
      len=child.len;
      count++;
      node->count=count;
    }
  }
  return node;
}
