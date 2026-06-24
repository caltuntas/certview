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

block_list_t *preprocess(uint8_t *msg,size_t len);
void be_uint64_to_array(uint64_t w,uint8_t arr[8]);
uint64_t be_uint64_from_array(uint8_t arr[8]);

#endif
