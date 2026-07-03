#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

typedef struct block_t {
  uint8_t buffer[64];
} block_t;

typedef struct block_list_t {
  size_t count;
  block_t *blocks;
} block_list_t;

block_list_t *sha256_preprocess(uint8_t *msg,size_t len);
uint32_t sha256_choose(uint32_t e,uint32_t f,uint32_t g);
uint32_t sha256_majority(uint32_t e,uint32_t f,uint32_t g);
void be_uint64_to_array(uint64_t w,uint8_t arr[8]);
uint8_t rotate_right8(uint8_t num,uint8_t count);
uint32_t rotate_right32(uint32_t num,uint32_t count);
uint64_t be_uint64_from_array(uint8_t arr[8]);
uint32_t sha256_sigma1(uint32_t num);
uint32_t sha256_sigma0(uint32_t num);
uint32_t sha256_s0(uint32_t num);
uint32_t sha256_s1(uint32_t num);
void sha256_split_blocks(uint8_t block[64],size_t len,uint32_t words[16]);
void sha256_message_schedule(uint32_t words[16],uint32_t expanded_words[64]);

#endif
