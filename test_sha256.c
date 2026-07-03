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
  block_list_t *list=sha256_preprocess(msg,ARRAY_LEN(msg));
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
  block_list_t *list = sha256_preprocess(msg, ARRAY_LEN(msg));
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
  block_list_t *list = sha256_preprocess(msg, ARRAY_LEN(msg));
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
  block_list_t *list = sha256_preprocess(msg, ARRAY_LEN(msg));
  block_t *b=&list->blocks[0];
  TEST_ASSERT_EQUAL_INT(3, list->count);
  uint8_t *len_ptr = &list->blocks[2].buffer[56];
  uint64_t len = be_uint64_from_array(len_ptr);
  TEST_ASSERT_EQUAL_INT(1040, len);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(b->buffer,block_expected,192);
}

static void test_choose()
{
  uint32_t e=0xF0F0F0F0;
  uint32_t f=0xAAAAAAAA;
  uint32_t g=0xCCCCCCCC;
  uint32_t expected=0xACACACAC;
  uint32_t result= sha256_choose(e,f,g);
  TEST_ASSERT_EQUAL_INT(expected, result);
}

static void test_majority()
{
  uint32_t e=0x33333333;
  uint32_t f=0x55555555;
  uint32_t g=0x77777777;
  uint32_t expected=0x77777777;
  uint32_t result= sha256_majority(e,f,g);
  TEST_ASSERT_EQUAL_INT(expected, result);
}

static void test_rotate_right8()
{
  uint8_t num=0b00111100;
  uint8_t expected=0b11100001;
  uint8_t result= rotate_right8(num,5);
  TEST_ASSERT_EQUAL_INT(expected, result);
}

static void test_rotate_right32()
{
  uint32_t actual  =0b00010010001101000101011001111111;
  uint32_t expected=0b11100001001000110100010101100111;
  uint32_t result= rotate_right32(actual,4);
  TEST_ASSERT_EQUAL_INT(expected, result);
}

static void test_sha256_sigma1()
{
  uint32_t E =0x510e527f;
  uint32_t result = sha256_sigma1(E);
  TEST_ASSERT_EQUAL_HEX32(0x3587272b, result);
}

static void test_sha256_sigma0()
{
  uint32_t A = 0x6a09e667; 
  uint32_t result = sha256_sigma0(A);
  TEST_ASSERT_EQUAL_HEX32(0xCE20B47E,result);
}

static void test_sha256_s0()
{
  uint32_t x = 0x41800000; 
  uint32_t result = sha256_s0(x);
  TEST_ASSERT_EQUAL_HEX32(0x08B31060, result);
}

static void test_sha256_s1()
{
  uint32_t x = 0x41800000; 
  uint32_t result = sha256_s1(x);
  TEST_ASSERT_EQUAL_HEX32(0x001048F0, result);
}

static void test_sha256_split_blocks()
{
  uint8_t msg[64]={
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x3C, 0x3D, 0x3E, 0x3F,
  };
  uint32_t out[16]={0};
  uint32_t words_expected[16]={0};
  words_expected[0]=0x00010203;
  words_expected[1]=0x04050607;
  words_expected[2]=0x08090A0B;
  words_expected[15]=0x3C3D3E3F;
  sha256_split_blocks(msg,ARRAY_LEN(msg),out);
  TEST_ASSERT_EQUAL_UINT32_ARRAY(out,words_expected,16);
}

static void test_sha256_message_schedule()
{
  uint32_t words[16]={
    0x61626380,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x18,
  };
  uint32_t out[64]={0};
  uint32_t words_expected[64]={
    0x61626380,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x18,
    0x61626380,
    0xF0000,
    0x7DA86405,
    0x600003C6,
    0x3E9D7B78,
    0x183FC00,
    0x12DCBFDB,
    0xE2E2C38E,
    0xC8215C1A,
    0xB73679A2,
    0xE5BC3909,
    0x32663C5B,
    0x9D209D67,
    0xEC8726CB,
    0x702138A4,
    0xD3B7973B,
    0x93F5997F,
    0x3B68BA73,
    0xAFF4FFC1,
    0xF10A5C62,
    0xA8B3996,
    0x72AF830A,
    0x9409E33E,
    0x24641522,
    0x9F47BF94,
    0xF0A64F5A,
    0x3E246A79,
    0x27333BA3,
    0xC4763F2,
    0x840ABF27,
    0x7A290D5D,
    0x65C43DA,
    0xFB3E89CB,
    0xCC7617DB,
    0xB9E66C34,
    0xA9993667,
    0x84BADEDD,
    0xC21462BC,
    0x1487472C,
    0xB20F7A99,
    0xEF57B9CD,
    0xEBE6B238,
    0x9FE3095E,
    0x78BC8D4B,
    0xA43FCF15,
    0x668B2FF8,
    0xEEABA2CC,
    0x12B1EDEB,
  };
  sha256_message_schedule(words,out);
  TEST_ASSERT_EQUAL_UINT32_ARRAY(out,words_expected,64);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_preprocess_small_message);
  RUN_TEST(test_preprocess_boundary_one_block);
  RUN_TEST(test_preprocess_boundary_two_blocks);
  RUN_TEST(test_preprocess_large_message);
  RUN_TEST(test_choose);
  RUN_TEST(test_majority);
  RUN_TEST(test_rotate_right8);
  RUN_TEST(test_sha256_sigma1);
  RUN_TEST(test_sha256_sigma0);
  RUN_TEST(test_sha256_s0);
  RUN_TEST(test_sha256_s1);
  RUN_TEST(test_sha256_split_blocks);
  RUN_TEST(test_sha256_message_schedule);
  return UNITY_END();
}
