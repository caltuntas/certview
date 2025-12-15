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
