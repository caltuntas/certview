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

uint32_t be_uint32_from_array(uint8_t arr[4]) {
  uint32_t res = 0;
  res |= (uint32_t)arr[0] << 24;
  res |= (uint32_t)arr[1] << 16;
  res |= (uint32_t)arr[2] << 8;
  res |= (uint32_t)arr[3] << 0;
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

void be_uint32_to_array(uint32_t w,uint8_t arr[4]) {
  arr[0] = w >> 24;
  arr[1] = w >> 16;
  arr[2] = w >> 8;
  arr[3] = w >> 0;
}

block_list_t *sha256_preprocess(uint8_t *msg,size_t len)
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

uint32_t sha256_choose(uint32_t e,uint32_t f,uint32_t g)
{
  return (e & f) ^ (~e & g);
}

uint32_t sha256_majority(uint32_t e,uint32_t f,uint32_t g)
{
  return (e & f) ^ (e & g) ^ (f & g);
}

uint8_t rotate_right8(uint8_t num,uint8_t count)
{
  return (num >> count)|(num << (8-count));
}

uint32_t rotate_right32(uint32_t num,uint32_t count)
{
  return (num >> count)|(num << (32-count));
}

uint32_t sha256_sigma1(uint32_t num)
{
  return rotate_right32(num,6) ^ rotate_right32(num,11) ^ rotate_right32(num,25);
}

uint32_t sha256_sigma0(uint32_t num)
{
  return rotate_right32(num,2) ^ rotate_right32(num,13) ^ rotate_right32(num,22);
}

uint32_t sha256_s0(uint32_t num)
{
  uint32_t res=rotate_right32(num,7) ^ rotate_right32(num,18) ^ (num >> 3);
  return res;
}

uint32_t sha256_s1(uint32_t num)
{
  uint32_t res=rotate_right32(num,17) ^ rotate_right32(num,19) ^ (num >> 10);
  return res;
}

void sha256_split_blocks(uint8_t block[64],size_t len,uint32_t words[16])
{
  for(int i=0,j=0; i<64; i+=4,j++){
    uint32_t word=be_uint32_from_array(block+i);
    words[j]=word;
  }
}

void sha256_message_schedule(uint32_t words[16],uint32_t expanded_words[64])
{
  for(int i=0; i<64; i++){
    if (i<=15) {
      expanded_words[i]=words[i];
    }else {
      int32_t s0=sha256_s0(expanded_words[i-15]);
      int32_t s1=sha256_s1(expanded_words[i-2]);
      expanded_words[i]=expanded_words[i-16]+s0+expanded_words[i-7]+s1;
    }
  }
}
