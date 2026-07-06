#include <stdlib.h>
#include <string.h>
#include "sha256.h"


uint32_t h0 = 0x6a09e667;
uint32_t h1 = 0xbb67ae85;
uint32_t h2 = 0x3c6ef372;
uint32_t h3 = 0xa54ff53a;
uint32_t h4 = 0x510e527f;
uint32_t h5 = 0x9b05688c;
uint32_t h6 = 0x1f83d9ab;
uint32_t h7 = 0x5be0cd19;

uint32_t K[64]={
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

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

sha256_state_t sha256_compress_round(sha256_state_t state,uint32_t word, uint32_t k)
{
  sha256_state_t newstate={0};
  uint32_t S1=sha256_sigma1(state.e);
  uint32_t ch=sha256_choose(state.e,state.f,state.g);
  uint32_t temp1=state.h+S1+ch+k+word;
  uint32_t S0=sha256_sigma0(state.a);
  uint32_t maj=sha256_majority(state.a,state.b,state.c);
  uint32_t temp2=S0+maj;
  newstate.a=temp1+temp2;
  newstate.b=state.a;
  newstate.c=state.b;
  newstate.d=state.c;
  newstate.e=state.d+temp1;
  newstate.f=state.e;
  newstate.g=state.f;
  newstate.h=state.g;
  return newstate;
}

sha256_state_t sha256_compress(sha256_state_t state,uint32_t words[64])
{
  sha256_state_t newstate=state;
  for(int i=0; i<64; i++){
    newstate=sha256_compress_round(newstate,words[i],K[i]);
  }
  return newstate;
}

void sha256_hash(uint8_t *msg,size_t len,uint8_t out[32])
{
  block_list_t *list = sha256_preprocess(msg,len);
  sha256_state_t state={
    .a = h0,
    .b = h1,
    .c = h2,
    .d = h3,
    .e = h4,
    .f = h5,
    .g = h6,
    .h = h7,
  };
  for(int i=0; i<list->count; i++){
    block_t block=list->blocks[i];
    uint32_t out[16]={0};
    sha256_split_blocks(block.buffer,64,out);
    uint32_t expanded_words[64]={0};
    sha256_message_schedule(out,expanded_words);
    state=sha256_compress(state,expanded_words);
  }
  h0=h0+state.a;
  h1=h1+state.b;
  h2=h2+state.c;
  h3=h3+state.d;
  h4=h4+state.e;
  h5=h5+state.f;
  h6=h6+state.g;
  h7=h7+state.h;

  be_uint32_to_array(h0,out);
  be_uint32_to_array(h1,out+4);
  be_uint32_to_array(h2,out+8);
  be_uint32_to_array(h3,out+12);
  be_uint32_to_array(h4,out+16);
  be_uint32_to_array(h5,out+20);
  be_uint32_to_array(h6,out+24);
  be_uint32_to_array(h7,out+28);
}
