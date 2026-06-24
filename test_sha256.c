#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sha256.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))

void setUp(void)
{
}

void tearDown(void)
{
}

static void test_preprocess_small_message()
{
  uint8_t msg[]={0x41};
  uint8_t block_expected[64]={0};
  block_expected[0]=0x41;
  block_expected[1]=0x80;
  block_expected[63]=0x08;
  block_list_t *list=preprocess(msg,ARRAY_LEN(msg));
  TEST_ASSERT_EQUAL_INT(1,list->count);
  block_t *b=&list->blocks[0];
  uint8_t *len_ptr = &list->blocks[0].buffer[56];
  uint64_t len=be_uint64_from_array(len_ptr);
  TEST_ASSERT_EQUAL_INT(8,len);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(b->buffer,block_expected,64);
}

static void test_preprocess_boundary_one_block()
{
  uint8_t msg[55];
  uint8_t block_expected[64]={0};
  memset(block_expected, 0x41, 55); 
  block_expected[55]=0x80;
  block_expected[62]=0x01;
  block_expected[63]=0xB8;
  memset(msg, 0x41, 55); 
  block_list_t *list = preprocess(msg, ARRAY_LEN(msg));
  block_t *b=&list->blocks[0];
  TEST_ASSERT_EQUAL_INT(1, list->count);
  uint8_t *len_ptr = &list->blocks[0].buffer[56];
  uint64_t len = be_uint64_from_array(len_ptr);
  TEST_ASSERT_EQUAL_INT(440, len);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(b->buffer,block_expected,64);
}

static void test_preprocess_boundary_two_blocks()
{
  uint8_t msg[56];
  uint8_t block_expected[128]={0};
  memset(block_expected, 0x41, 56); 
  block_expected[56]=0x80;
  block_expected[126]=0x01;
  block_expected[127]=0xC0;
  memset(msg, 0x41, 56); 
  block_list_t *list = preprocess(msg, ARRAY_LEN(msg));
  block_t *b=&list->blocks[0];
  TEST_ASSERT_EQUAL_INT(2, list->count);
  uint8_t *len_ptr = &list->blocks[1].buffer[56];
  uint64_t len = be_uint64_from_array(len_ptr);
  TEST_ASSERT_EQUAL_INT(448, len);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(b->buffer,block_expected,128);
}

static void test_preprocess_large_message()
{
  uint8_t msg[130];
  uint8_t block_expected[192]={0};
  memset(block_expected, 0x41, 130); 
  block_expected[130]=0x80;
  block_expected[190]=0x04;
  block_expected[191]=0x10;
  memset(msg, 0x41, 130);
  block_list_t *list = preprocess(msg, ARRAY_LEN(msg));
  block_t *b=&list->blocks[0];
  TEST_ASSERT_EQUAL_INT(3, list->count);
  uint8_t *len_ptr = &list->blocks[2].buffer[56];
  uint64_t len = be_uint64_from_array(len_ptr);
  TEST_ASSERT_EQUAL_INT(1040, len);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(b->buffer,block_expected,192);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_preprocess_small_message);
  RUN_TEST(test_preprocess_boundary_one_block);
  RUN_TEST(test_preprocess_boundary_two_blocks);
  RUN_TEST(test_preprocess_large_message);
  return UNITY_END();
}
