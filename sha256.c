#include <stdlib.h>
#include <string.h>
#include "sha256.h"

uint64_t be_uint64_from_array(uint8_t arr[8]) {
  uint64_t res = 0;
  res |= (uint64_t)arr[0] << 56;
  res |= (uint64_t)arr[1] << 48;
  res |= (uint64_t)arr[2] << 40;
  res |= (uint64_t)arr[3] << 32;
  res |= (uint64_t)arr[4] << 24;
  res |= (uint64_t)arr[5] << 16;
  res |= (uint64_t)arr[6] << 8;
  res |= (uint64_t)arr[7] << 0;
  return res;
}

void be_uint64_to_array(uint64_t w,uint8_t arr[8]) {
  arr[0] = w >> 56;
  arr[1] = w >> 48;
  arr[2] = w >> 40;
  arr[3] = w >> 32;
  arr[4] = w >> 24;
  arr[5] = w >> 16;
  arr[6] = w >> 8;
  arr[7] = w >> 0;
}


block_list_t *preprocess(uint8_t *msg,size_t len)
{
  block_list_t *list=malloc(sizeof(*list));
  
  int count = 0;
  uint64_t len_byte=len*8;
  uint8_t pad1=0x80;
  count = (len*8)/(512-64)+1;
  list->blocks=malloc(sizeof(block_t)*count);
  uint8_t len_buffer[8]={0};
  be_uint64_to_array(len_byte,len_buffer);
  memcpy(list->blocks,msg,len);
  memcpy((char*)list->blocks+len,&pad1,1);
  list->count=count;
  list->blocks[count-1].buffer[56]=len_buffer[0];
  list->blocks[count-1].buffer[57]=len_buffer[1];
  list->blocks[count-1].buffer[58]=len_buffer[2];
  list->blocks[count-1].buffer[59]=len_buffer[3];
  list->blocks[count-1].buffer[60]=len_buffer[4];
  list->blocks[count-1].buffer[61]=len_buffer[5];
  list->blocks[count-1].buffer[62]=len_buffer[6];
  list->blocks[count-1].buffer[63]=len_buffer[7];
  return list;
}
