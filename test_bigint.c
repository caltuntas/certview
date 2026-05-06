#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bigint.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))
#define BIGINT(sign,...) (bigint_t){sign,(uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__})}

typedef struct {
  char *x;
  char *y;
  char *result;
  int base;
} test_case_mul;

typedef struct {
  bigint_t num1;
  bigint_t num2;
  bigint_t result;
} test_case_bigint_two_operands;

typedef struct {
  bigint_t dividend;
  bigint_t divisor;
  bigint_t quotient;
  bigint_t remainder;
} test_case_bigint_division;

typedef struct {
  bigint_t num1;
  int bits;
  bigint_t result;
} test_case_bigint_bit_shift;

typedef struct {
  uint8_t *hex;
  size_t length;
  bigint_t result;
} test_case_bigint_create;

typedef struct {
  bigint_t bigint;
  char *result;
} test_case_bigint_to_decimal;

typedef struct {
  char *decimal;
  bigint_t bigint;
} test_case_decimal_to_hex;

typedef struct {
  char *x;
  char *y;
  int result;
} test_case_compare;

typedef struct {
  bigint_t num1;
  bigint_t num2;
  int result;
} test_case_compare_bigint;

typedef struct {
  bigint_t dividend;
  bigint_t divisor;
  bigint_t expected;
} test_case_gcd;

typedef struct {
  bigint_t a;
  bigint_t b;
  bigint_t g;
  bigint_t x;
  bigint_t y;
} test_case_xgcd;

typedef struct {
  bigint_t num;
  bigint_t divisor;
  bigint_t expected;
} test_case_modinv;


void print_data(uint8_t *data,size_t len)
{
  for (int i=0;i<len; i++) {
    printf("%02X,",data[i]);
  }
  printf("\n");
}


void setUp(void)
{
}

void tearDown(void)
{
}

static void test_mul_bigint(void)
{
  test_case_bigint_two_operands cases[] = {
    { BIGINT(NON_NEGATIVE,0x05),BIGINT(NON_NEGATIVE,0x10),BIGINT(NON_NEGATIVE,0x50) },
    { BIGINT(NON_NEGATIVE,0x07),BIGINT(NON_NEGATIVE,0x10),BIGINT(NON_NEGATIVE,0x70) },
    { BIGINT(NON_NEGATIVE,0x0C),BIGINT(NON_NEGATIVE,0x10),BIGINT(NON_NEGATIVE,0xC0),},
    { BIGINT(NON_NEGATIVE,0x05),BIGINT(NON_NEGATIVE,0x35),BIGINT(NON_NEGATIVE,0x01,0x09) },
    { BIGINT(NON_NEGATIVE,0x07),BIGINT(NON_NEGATIVE,0x08),BIGINT(NON_NEGATIVE,0x38) },
    { BIGINT(NON_NEGATIVE,0xFA,0xCA),BIGINT(NON_NEGATIVE,0x02,0x03),BIGINT(NON_NEGATIVE,0x01,0xF8,0x84,0x5E) },
    { BIGINT(NON_NEGATIVE,0XAB,0X54,0XA9,0X8C,0XEB,0X1F,0X0A,0XD2),BIGINT(NON_NEGATIVE,0X10),BIGINT(NON_NEGATIVE,0X0A,0XB5,0X4A,0X98,0XCE,0XB1,0XF0,0XAD,0X20)},
  };
  size_t len=ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_bigint_two_operands tc=cases[i];
    bigint_t *result =mul_bigint(&tc.num1,&tc.num2);
    char *strnum1 =bigint_to_decimal_str(&tc.num1);
    char *strnum2 =bigint_to_decimal_str(&tc.num2);
    char *strres =bigint_to_decimal_str(result);
    printf("%sx%s=%s\n",strnum1,strnum2,strres);
    TEST_ASSERT_EQUAL_INT(tc.result.length,result->length);
    TEST_ASSERT_EQUAL_INT(tc.result.sign,result->sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.result.data,result->data,tc.result.length);
  }
}


static void test_bigint_create(void)
{
	test_case_bigint_create cases[] = {
		{(uint8_t[]){0xFA,0xCE},2,BIGINT(NEGATIVE,0x05,0x32)}, //"-1330"
		{(uint8_t[]){0x00,0x87},2,BIGINT(NON_NEGATIVE,0x87)},//"135"
		{(uint8_t[]){0xFF,0xFF,0xFF,0xFF},4,BIGINT(NEGATIVE,0x01)},//"-1"
		{(uint8_t[]){0x01,0x00,0x00,0x00,0x00},5,BIGINT(NON_NEGATIVE,0x01,0x00,0x00,0x00,0x00)},//"4294967296"
		{(uint8_t[]){0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},8,BIGINT(NEGATIVE,0x01)},//"-1"
		{(uint8_t[]){0xFF},1,BIGINT(NEGATIVE,0x01)},//"-1"
		{(uint8_t[]){0xFF,0x00},2,BIGINT(NEGATIVE,0x01,0x00)},//"-256"
		{(uint8_t[]){0x80},1,BIGINT(NEGATIVE,0x80)},//"-128"
		{(uint8_t[]){0x00,0x80},2,BIGINT(NON_NEGATIVE,0x80)},//"128"
		{(uint8_t[]){0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},9,BIGINT(NEGATIVE,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)},//"-2361183241434822606848"
	};
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_bigint_create tc=cases[i];
    bigint_t *actual=create_bigint(tc.hex,tc.length);
    char *decimal_str =bigint_to_decimal_str(actual);
    printf("case=%d %s\n",i,decimal_str);
    TEST_ASSERT_EQUAL_INT(actual->sign,tc.result.sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(actual->data,tc.result.data,tc.result.length);
	}
}


static void test_bigint_to_decimal(void)
{
  test_case_bigint_to_decimal cases[] = {
    { BIGINT(NON_NEGATIVE,0x00),"0"},
    { BIGINT(NEGATIVE,0x05,0x32),"-1330"},
    { BIGINT(NON_NEGATIVE,0x87),"135"},
    { BIGINT(NEGATIVE,0x01),"-1"},
    { BIGINT(NON_NEGATIVE,0x01,0x00,0x00,0x00,0x00),"4294967296"},
    { BIGINT(NON_NEGATIVE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF),"18446744073709551615"},
    { BIGINT(NON_NEGATIVE,0xFF),"255"},
    { BIGINT(NON_NEGATIVE,0xFF,0x00),"65280"},
    { BIGINT(NEGATIVE,0x01,0x00),"-256"},
    { BIGINT(NON_NEGATIVE,0x80),"128"},
    { BIGINT(NEGATIVE,0x80),"-128"},
    { BIGINT(NEGATIVE,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00),"-2361183241434822606848"},
    { BIGINT(NON_NEGATIVE,0xC0),"192"},
  };
  size_t len=ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_bigint_to_decimal tc=cases[i];
    char *result =bigint_to_decimal_str(&tc.bigint);
    TEST_ASSERT_EQUAL_STRING(tc.result,result);
  }
}


static void test_decimal_to_bigint(void)
{
	test_case_decimal_to_hex cases[] = {
		{"0",BIGINT(NON_NEGATIVE,0x00)},
		{"00",BIGINT(NON_NEGATIVE,0x00)},
		{"000",BIGINT(NON_NEGATIVE,0x00)},
		{"1",BIGINT(NON_NEGATIVE,0x01)},
		{"9",BIGINT(NON_NEGATIVE,0x09)},
		{"10",BIGINT(NON_NEGATIVE,0x0A)},
		{"135",BIGINT(NON_NEGATIVE,0x87)},
		{"255",BIGINT(NON_NEGATIVE,0xFF)},
		{"256",BIGINT(NON_NEGATIVE,0x01,0x00)},
		{"257",BIGINT(NON_NEGATIVE,0x01,0x01)},
		{"511",BIGINT(NON_NEGATIVE,0x01,0xFF)},
		{"512",BIGINT(NON_NEGATIVE,0x02,0x00)},
		{"1330",BIGINT(NON_NEGATIVE,0x05,0x32)},
		{"65537",BIGINT(NON_NEGATIVE,0x01,0x00,0x01)},
		{"4294967296",BIGINT(NON_NEGATIVE, 0x01,0x00,0x00,0x00,0x00)},
		{
      "9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
      BIGINT(1,0x03,0xCE,0x36,0xC7,0xE7,0x74,0xF6,0xB0,0x15,0xE3,0x4A,0x5A,0x54,0xE6,0xF2,0xDB,0x4A,0xBE,0x87,0xCA,0xB2,0xAE,0x32,0xC7,0xA3,0xE8,0xEC,0xF3,0x64,0x53,0xB5,0x9A,0xA2,0x14,0x6B,0x2F,0x11,0x21,0xD5,0xEF,0xD7,0xF1,0x5C,0xD3,0x77,0x54,0x8E,0xAF,0x62,0x03,0x41,0x04,0x8F,0x59,0xA7,0x22,0xF1,0x2A,0x84,0x8A,0xFB,0x44,0x3A,0xE8,0xC1,0x8F,0xC6,0xE6,0x2B,0xF6,0x17,0x29,0x55,0x51,0x0A,0xDF,0xB8,0x4E,0x6B,0xAA,0x16,0x6A,0x05,0x68,0x64,0x1B,0x9E,0x86,0x94,0x9F,0x98,0x5D,0xA7,0xD2,0x53,0x3B,0xE0,0x9B,0x67,0xA0,0xE5,0x42,0xC3,0xB5,0x95,0x40,0x22,0x8D,0x98,0xEC,0x4E,0x3D,0x9D,0x71,0x0E,0xE0,0xFE,0x77,0x72,0x9D,0x7E,0x46,0x98,0xF0,0xC0,0x81,0x62,0x80,0xA2,0x82,0xE5,0x3B,0x34,0xE5,0x60,0xA0,0x16,0x5D,0x55,0x52,0x2A,0xEA,0x78,0x7D,0xA0,0xBC,0x3E,0xB5,0xAF,0xF7,0xD4,0x90,0x93,0xCB,0x88,0x3E,0xF5,0x3C,0xD3,0x9C,0x82,0xB3,0x96,0xF9,0x5C,0xAD,0xA8,0x8C,0x2F,0xB7,0x2D,0xCC,0xB2,0x43,0xD3,0x67,0x8B,0x85,0xC6,0x21,0x1E,0xCC,0x86,0x7A,0x00,0x0D,0x77,0x9C,0x22,0x59,0x99,0xCC,0xDD,0x06,0xFC,0x1A,0x82,0x98,0xBF,0x7F,0x6E,0x51,0x3B,0x49,0x19,0x81,0xAB,0x18,0x5D,0x4A,0xF8,0xFD,0x07,0xB5,0x14,0xA9,0x3A,0xD9,0x5B,0x67,0x0D,0xBD,0x77,0x4E,0xC6,0x86,0x4A,0x22,0xC3,0x87,0x59,0x1B,0x3B,0xC7,0x9D,0x16,0xD4,0xCC,0x76,0xA1,0xBC,0xA9,0xA9,0x4B,0x7A,0xD1,0x05,0x84,0xA4,0x87,0x74,0x78,0x61,0x2D,0xDB,0x69,0x80,0x5E,0x7C,0x32,0xC5,0x27,0x90,0xD3,0x9B,0xCB,0x19,0x48,0x4B,0x53,0x8E,0x80,0x21,0xF4,0x55,0xB4,0x26,0xE5,0xD5,0x8F,0x9A,0xC2,0x97,0xA7,0x5F,0x46,0x3C,0xE7,0x6E,0x26,0x60,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF)
    },
	};
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_decimal_to_hex tc=cases[i];
		bigint_t *bi =bigint_from_decimal_str(tc.decimal);
    printf("case=%d %s\n",i,tc.decimal);
    //print_data(bi->data,bi->length);
		TEST_ASSERT_EQUAL_INT(tc.bigint.length,bi->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.bigint.data,bi->data,tc.bigint.length);
	}
}


static void test_add_bigint(void)
{
  test_case_bigint_two_operands cases[] = {
    { BIGINT(1,0x05), BIGINT(1,0x10), BIGINT(1,0x15) },
    { BIGINT(1,0x07), BIGINT(1,0x10), BIGINT(1,0x17) },
    { BIGINT(1,0x0C), BIGINT(1,0x10), BIGINT(1,0x1C) },
    { BIGINT(1,0x04,0xE2), BIGINT(1,0x19), BIGINT(1,0x04,0xFB) },
    { BIGINT(1,0x2A), BIGINT(1,0x46), BIGINT(1,0x70) },
    { BIGINT(1,0x03, 0xE7), BIGINT(1,0x01), BIGINT(1,0x03, 0xE8) },
    { BIGINT(1,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF), BIGINT(1,0x0F), BIGINT(1,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0E) },
    { BIGINT(1,0x00), BIGINT(1,0x00), BIGINT(1,0x00) },
    { BIGINT(1,0x00), BIGINT(1,0x15), BIGINT(1,0x15) },
    { BIGINT(1,0x2A), BIGINT(1,0x00), BIGINT(1,0x2A) },
    { BIGINT(1,0xFF), BIGINT(1,0x01), BIGINT(1,0x01,0x00) },
    { BIGINT(1,0xFE), BIGINT(1,0x02), BIGINT(1,0x01,0x00) },
    { BIGINT(1,0xFF,0xFF), BIGINT(1,0x01), BIGINT(1,0x01,0x00,0x00) },
    { BIGINT(1,0x12,0xFF,0xFF), BIGINT(1,0x01), BIGINT(1,0x13,0x00,0x00) },
    { BIGINT(1,0x01), BIGINT(1,0x01,0x00), BIGINT(1,0x01,0x01) },
    { BIGINT(1,0xFF), BIGINT(1,0x01,0x00), BIGINT(1,0x01,0xFF) },
    { BIGINT(1,0x10,0x20), BIGINT(1,0x01), BIGINT(1,0x10,0x21) },
    { BIGINT(1,0x01,0x00), BIGINT(1,0x01), BIGINT(1,0x01,0x01) },
    { BIGINT(1,0xAB,0xCD), BIGINT(1,0x01), BIGINT(1,0xAB,0xCE) },
    { BIGINT(1,0xFF,0xFF,0xFF), BIGINT(1,0x01), BIGINT(1,0x01,0x00,0x00,0x00) },
    { BIGINT(1,0x00,0x01), BIGINT(1,0x01), BIGINT(1,0x02) },
    { BIGINT(1,0x00,0xFF), BIGINT(1,0x01), BIGINT(1,0x01,0x00) },
    { BIGINT(1,0x7F,0xFF,0xFF,0xFF), BIGINT(1,0x01), BIGINT(1,0x80,0x00,0x00,0x00) },
    { BIGINT(1,0x12,0x34,0x56,0x78,0x9A), BIGINT(1,0x87,0x65,0x43,0x21), BIGINT(1,0x12,0xBB,0xBB,0xBB,0xBB) },
    //signed addition test cases
    { BIGINT(-1,0x05), BIGINT(-1,0x03), BIGINT(-1,0x08) },
    { BIGINT(-1,0xFF), BIGINT(-1,0x01), BIGINT(-1,0x01,0x00) },
    { BIGINT(1,0x10), BIGINT(-1,0x05), BIGINT(1,0x0B) },
    { BIGINT(1,0x20), BIGINT(-1,0x01), BIGINT(1,0x1F) },
    { BIGINT(1,0x05), BIGINT(-1,0x10), BIGINT(-1,0x0B) },
    { BIGINT(1,0x01), BIGINT(-1,0xFF), BIGINT(-1,0xFE) },
    { BIGINT(1,0x05), BIGINT(-1,0x05), BIGINT(1,0x00) },
    { BIGINT(-1,0xAB,0xCD), BIGINT(1,0xAB,0xCD), BIGINT(1,0x00) },
    { BIGINT(1,0x01,0x00), BIGINT(-1,0x01), BIGINT(1,0xFF) }, // 256 - 1 = 255
    { BIGINT(1,0x10,0x00), BIGINT(-1,0x01), BIGINT(1,0x0F,0xFF) },
    { BIGINT(-1,0x10), BIGINT(1,0x01), BIGINT(-1,0x0F) },
    { BIGINT(-1,0x20), BIGINT(1,0x10), BIGINT(-1,0x10) },
    { BIGINT(1,0x7F,0xFF,0xFF), BIGINT(-1,0x01), BIGINT(1,0x7F,0xFF,0xFE) },
    { BIGINT(-1,0x80,0x00,0x00), BIGINT(1,0x01), BIGINT(-1,0x7F,0xFF,0xFF) },
    { BIGINT(1,0x00), BIGINT(-1,0x05), BIGINT(-1,0x05) },
    { BIGINT(-1,0x01), BIGINT(1,0x05), BIGINT(1,0x04) },
    { BIGINT(-1,0x00), BIGINT(1,0x05), BIGINT(1,0x05) },
    { BIGINT(-1,0x00), BIGINT(-1,0x00), BIGINT(1,0x00) },
    { BIGINT(1,0x33), BIGINT(-1,0x11), BIGINT(1,0x22) },
    { BIGINT(-1,0x11), BIGINT(1,0x33), BIGINT(1,0x22) },
  };
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_bigint_two_operands tc=cases[i];
    bigint_t *result =add_bigint(&tc.num1,&tc.num2);
    char *strnum1 =bigint_to_decimal_str(&tc.num1);
    char *strnum2 =bigint_to_decimal_str(&tc.num2);
    char *strres =bigint_to_decimal_str(result);
    printf("case %d (%s)+(%s)=%s\n",i,strnum1,strnum2,strres);
    TEST_ASSERT_EQUAL_INT(tc.result.sign,result->sign);
    TEST_ASSERT_EQUAL_INT(tc.result.length,result->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.result.data,result->data,tc.result.length);
	}
}

static void test_sub_bigint(void)
{
  test_case_bigint_two_operands cases[] = {
    { BIGINT(NON_NEGATIVE,0x00,0x2B,0x00),BIGINT(NON_NEGATIVE,0x00,0x2B,0x00),BIGINT(NON_NEGATIVE,0x00) },
    { BIGINT(NON_NEGATIVE,0x05),BIGINT(NON_NEGATIVE,0x03),BIGINT(NON_NEGATIVE,0x02) },
    { BIGINT(NON_NEGATIVE,0x0A),BIGINT(NON_NEGATIVE,0x04),BIGINT(NON_NEGATIVE,0x06) },
    { BIGINT(NON_NEGATIVE,0x64),BIGINT(NON_NEGATIVE,0x32),BIGINT(NON_NEGATIVE,0x32) },
    { BIGINT(NON_NEGATIVE,0xA3),BIGINT(NON_NEGATIVE,0x39),BIGINT(NON_NEGATIVE,0x6A) },
    { BIGINT(NON_NEGATIVE,0xA3),BIGINT(NON_NEGATIVE,0x43),BIGINT(NON_NEGATIVE,0x60) },
    { BIGINT(NON_NEGATIVE,0x0A),BIGINT(NON_NEGATIVE,0x01),BIGINT(NON_NEGATIVE,0x09) },
    { BIGINT(NON_NEGATIVE,0x64),BIGINT(NON_NEGATIVE,0x01),BIGINT(NON_NEGATIVE,0x63) },
    { BIGINT(NON_NEGATIVE,0x03,0xE8),BIGINT(NON_NEGATIVE,0x01),BIGINT(NON_NEGATIVE,0x03,0xE7) },
    { BIGINT(NON_NEGATIVE,0x27,0x10),BIGINT(NON_NEGATIVE,0x01),BIGINT(NON_NEGATIVE,0x27,0x0F) },
    { BIGINT(NON_NEGATIVE,0x01,0x86,0xA0),BIGINT(NON_NEGATIVE,0x01),BIGINT(NON_NEGATIVE,0X01,0X86,0X9F) },
    { BIGINT(NON_NEGATIVE,0x03,0xE8),BIGINT(NON_NEGATIVE,0x03,0xE7),BIGINT(NON_NEGATIVE,0x01) },
    { BIGINT(NON_NEGATIVE,0x27,0x10),BIGINT(NON_NEGATIVE,0x27,0x0F),BIGINT(NON_NEGATIVE,0x01) },
    { BIGINT(NON_NEGATIVE,0x01,0x86,0xA0),BIGINT(NON_NEGATIVE,0X01,0X86,0X9F),BIGINT(NON_NEGATIVE,0x01) },
    { BIGINT(NON_NEGATIVE,0xE8,0x03),BIGINT(NON_NEGATIVE,0xE7,0x03),BIGINT(NON_NEGATIVE,0x01,0x00) },
    { BIGINT(NON_NEGATIVE,0x10,0x27),BIGINT(NON_NEGATIVE,0x0F,0x27),BIGINT(NON_NEGATIVE,0x01,0x00) },
    { BIGINT(NON_NEGATIVE,0xA0,0x86,0x01),BIGINT(NON_NEGATIVE,0x9F,0x86,0x01),BIGINT(NON_NEGATIVE,0x01,0x00,0x00) },
    { BIGINT(NON_NEGATIVE,0x40,0x42,0x0F),BIGINT(NON_NEGATIVE,0x3F,0x42,0x0F),BIGINT(NON_NEGATIVE,0x01,0x00,0x00) },
    { BIGINT(1,0x10), BIGINT(1,0x05), BIGINT(1,0x0B) },
    { BIGINT(1,0x05), BIGINT(1,0x10), BIGINT(-1,0x0B) },
    { BIGINT(1,0xFF), BIGINT(1,0x01), BIGINT(1,0xFE) },
    { BIGINT(-1,0x10), BIGINT(-1,0x05), BIGINT(-1,0x0B) }, // -16 - (-5) = -11
    { BIGINT(-1,0x05), BIGINT(-1,0x10), BIGINT(1,0x0B) },  // -5 - (-16) = +11
    { BIGINT(1,0x10), BIGINT(-1,0x05), BIGINT(1,0x15) },
    { BIGINT(1,0xFF), BIGINT(-1,0x01), BIGINT(1,0x01,0x00) },
    { BIGINT(-1,0x10), BIGINT(1,0x05), BIGINT(-1,0x15) },
    { BIGINT(-1,0x01), BIGINT(1,0x01), BIGINT(-1,0x02) },
    { BIGINT(1,0x05), BIGINT(1,0x05), BIGINT(1,0x00) },
    { BIGINT(-1,0xAB,0xCD), BIGINT(-1,0xAB,0xCD), BIGINT(1,0x00) },
    { BIGINT(1,0x01,0x00), BIGINT(1,0x01), BIGINT(1,0xFF) }, // 256 - 1
    { BIGINT(1,0x10,0x00), BIGINT(1,0x01), BIGINT(1,0x0F,0xFF) },
    { BIGINT(1,0x01,0x00,0x00), BIGINT(1,0x01), BIGINT(1,0xFF,0xFF) },
    { BIGINT(1,0x05), BIGINT(1,0x10), BIGINT(-1,0x0B) },
    { BIGINT(-1,0x10), BIGINT(-1,0x20), BIGINT(1,0x10) },
    { BIGINT(1,0x01), BIGINT(1,0x01,0x00), BIGINT(-1,0xFF) },
    { BIGINT(1,0x01,0x00), BIGINT(1,0x01), BIGINT(1,0xFF) },
    { BIGINT(1,0x80,0x00,0x00), BIGINT(1,0x01), BIGINT(1,0x7F,0xFF,0xFF) },
    { BIGINT(1,0x7F,0xFF,0xFF), BIGINT(1,0x80,0x00,0x00), BIGINT(-1,0x01) },
    { BIGINT(-1,0x80,0x00,0x00), BIGINT(1,0x01), BIGINT(-1,0x80,0x00,0x01) },
    { BIGINT(1,0x00), BIGINT(1,0x05), BIGINT(-1,0x05) },
    { BIGINT(1,0x05), BIGINT(1,0x00), BIGINT(1,0x05) },
    { BIGINT(-1,0x00), BIGINT(1,0x05), BIGINT(-1,0x05) },
  };
  size_t len=ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_bigint_two_operands tc=cases[i];
    bigint_t *result =sub_bigint(&tc.num1,&tc.num2);
    bigint_t *negativeres =sub_bigint(&tc.num2,&tc.num1);
    char *strnum1 =bigint_to_decimal_str(&tc.num1);
    char *strnum2 =bigint_to_decimal_str(&tc.num2);
    char *strres =bigint_to_decimal_str(result);
    printf("case %d (%s)-(%s)=%s\n",i,strnum1,strnum2,strres);
    TEST_ASSERT_EQUAL_INT(tc.result.length,result->length);
    TEST_ASSERT_EQUAL_INT(tc.result.sign,result->sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.result.data,result->data,tc.result.length);

    TEST_ASSERT_EQUAL_INT(tc.result.length,negativeres->length);
    //if result is 0 sign cannot be flipped/negated
    if(tc.result.length!=1 && tc.result.data[0]!=0)
      TEST_ASSERT_NOT_EQUAL_INT(tc.result.sign,negativeres->sign);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.result.data,negativeres->data,tc.result.length);
  }
}

static void test_compare_bigint(void)
{
	test_case_compare_bigint cases[] = {
    { BIGINT(1,0x05), BIGINT(1,0x10), -1 },
    { BIGINT(1,0x07), BIGINT(1,0x10), -1 },
    { BIGINT(1,0x04,0xE2), BIGINT(1,0x19), 1 },
	};
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_compare_bigint tc=cases[i];
    char msg[40];
    snprintf(msg,20,"case=%d\n",i);
		int result =compare_bigint(&tc.num1,&tc.num2);
		TEST_ASSERT_EQUAL_MESSAGE(tc.result,result,msg);
	}
}

static void test_div_bigint(void)
{
  test_case_bigint_division cases[] = {
		{ BIGINT(1,0x07,0x5B,0xCD,0x15),BIGINT(1,0xBC,0x61,0x5F), BIGINT(1,9), BIGINT(1,0xBC,0x60,0xBE)},
		{ BIGINT(1,0x07,0x5B,0xCD,0x15),BIGINT(1,0x3B,0x9A,0xCA,0x07),BIGINT(1,0),BIGINT(1,0x07,0x5B,0xCD,0x15)},
    { BIGINT(NON_NEGATIVE,0xAA,0x12,0xFE,0x01),BIGINT(1,0x0F,0xAB),BIGINT(1,0x0A,0xDA,0xDA),BIGINT(1,0x08,0x63) },
    { BIGINT(1,0x12,0x34,0x56),BIGINT(1,0x01),BIGINT(1,0x12,0x34,0x56),BIGINT(1,0x00) },
    { BIGINT(1,0xFF,0xFF,0xFF),BIGINT(1,0xFF),BIGINT(1,0x01,0x01,0x01),BIGINT(1,0x00) },
    { BIGINT(1,0xFF,0xFE),BIGINT(1,0x02),BIGINT(1,0x7F,0xFF),BIGINT(1,0x00) },
    { BIGINT(1,0x01,0x00),BIGINT(1,0x02),BIGINT(1,0x80),BIGINT(1,0x00) },
    { BIGINT(1,0x03,0x00),BIGINT(1,0x03),BIGINT(1,0x01,0x00),BIGINT(1,0x00) },
    { BIGINT(1,0xFF,0xFF),BIGINT(1,0x03),BIGINT(1,0x55,0x55),BIGINT(1,0x00) },
    { BIGINT(1,0xFF,0x00),BIGINT(1,0xFF),BIGINT(1,0x01,0x00),BIGINT(1,0x00) },
    { BIGINT(1,0xFE,0x01),BIGINT(1,0xFE),BIGINT(1,0x01,0x00),BIGINT(1,0x01) },
    { BIGINT(1,0x80,0x00),BIGINT(1,0x80),BIGINT(1,0x01,0x00),BIGINT(1,0x00) },
    { BIGINT(1,0xFF,0xFF),BIGINT(1,0x80),BIGINT(1,0x01,0xFF),BIGINT(1,0x7F) },
    { BIGINT(1,0x12,0x34,0x56),BIGINT(1,0x01),BIGINT(1,0x12,0x34,0x56),BIGINT(1,0x00) },
    { BIGINT(1,0x10),BIGINT(1,0x20),BIGINT(1,0x00),BIGINT(1,0x10) },
    { BIGINT(1,0x01,0x00),BIGINT(1,0xFF),BIGINT(1,0x01),BIGINT(1,0x01) },
    { BIGINT(1,0x01,0x00,0x00),BIGINT(1,0x02),BIGINT(1,0x80,0x00),BIGINT(1,0x00) },
    { BIGINT(1,0x02,0x00,0x00),BIGINT(1,0x02),BIGINT(1,0x01,0x00,0x00),BIGINT(1,0x00) },
    { BIGINT(1,0xFF,0xFF,0xFF,0xFF),BIGINT(1,0x02),BIGINT(1,0x7F,0xFF,0xFF,0xFF),BIGINT(1,0x01) },
    { BIGINT(1,0xFF,0xFF,0xFF,0xFF),BIGINT(1,0x0F),BIGINT(1,0x11,0x11,0x11,0x11),BIGINT(1,0x00) },
    { BIGINT(1,0xAA,0xAA,0xAA),BIGINT(1,0x02),BIGINT(1,0x55,0x55,0x55),BIGINT(1,0x00) },
    { BIGINT(1,0x55,0x55,0x55),BIGINT(1,0x05),BIGINT(1,0x11,0x11,0x11),BIGINT(1,0x00) },
    { BIGINT(1,0x00,0xFF,0xFF),BIGINT(1,0x02),BIGINT(1,0x7F,0xFF),BIGINT(1,0x01) },
    { BIGINT(1,0x12,0x34,0x56,0x78),BIGINT(1,0x12,0x34),BIGINT(1,0x01,0x00,0x04),BIGINT(1,0x0D,0xA8) },
    { BIGINT(1,0xAA,0xBB,0xCC,0xDD),BIGINT(1,0x01,0x23,0x45),BIGINT(1,0x96,0x0F),BIGINT(1,0x4D,0xD2) },
    { BIGINT(1,0x10,0x00,0x00,0x00),BIGINT(1,0x01,0x00),BIGINT(1,0x10,0x00,0x00),BIGINT(1,0x00) },
    { BIGINT(1,0x01,0x00,0x00,0x00),BIGINT(1,0xFF,0xFF),BIGINT(1,0x01,0x00),BIGINT(1,0x01,0x00) },
    { BIGINT(1,0x20,0x00,0x00,0x00),BIGINT(1,0x1F,0xFF,0xFF),BIGINT(1,0x01,0x00),BIGINT(1,0x01,0x00) },
    { BIGINT(1,0xFF,0xFF,0xFF,0xFF,0xFF),BIGINT(1,0xFF,0xFF),BIGINT(1,0x01,0x00,0x01,0x00),BIGINT(1,0xFF) },
    { BIGINT(1,0xAA,0xAA,0xAA,0xAA),BIGINT(1,0x55,0x55),BIGINT(1,0x02,0x00,0x02),BIGINT(1,0x00) },
    { BIGINT(1,0x01,0x00,0x00,0x00,0x00),BIGINT(1,0x01,0x00,0x00),BIGINT(1,0x01,0x00,0x00),BIGINT(1,0x00) },
    { BIGINT(1,0x12,0x34,0x56),BIGINT(1,0x12,0x34,0x55),BIGINT(1,0x01),BIGINT(1,0x01) },
    { BIGINT(1,0xDE,0xAD,0xBE,0xEF,0x12,0x34),BIGINT(1,0xBE,0xEF,0x01),BIGINT(1,0X01,0X2A,0X90,0X2C),BIGINT(1,0x83,0x6E,0x08) },
    { BIGINT(1,0xFF,0xEE,0xDD),BIGINT(1,0xFF,0xEE),BIGINT(1,0x01,0x00),BIGINT(1,0xDD) },
    { BIGINT(1,0x01,0x23,0x45,0x67,0x89),BIGINT(1,0x01,0x23,0x45),BIGINT(1,0x01,0x00,0x00),BIGINT(1,0x67,0x89) },
    //signed division
    { BIGINT(-1, 0x10), BIGINT(1, 0x02), BIGINT(-1, 0x08) },
    { BIGINT(1, 0x10), BIGINT(-1, 0x02), BIGINT(-1, 0x08) },
    { BIGINT(-1, 0x10), BIGINT(-1, 0x02), BIGINT(1, 0x08) },
    { BIGINT(1, 0x11), BIGINT(1, 0x02), BIGINT(1, 0x08) },
    { BIGINT(-1, 0x11), BIGINT(1, 0x02), BIGINT(-1, 0x08) },
    { BIGINT(1, 0x11), BIGINT(-1, 0x02), BIGINT(-1, 0x08) },
    { BIGINT(-1, 0x11), BIGINT(-1, 0x02), BIGINT(1, 0x08) },
    { BIGINT(-1, 0xAA,0xBB,0xCC), BIGINT(1, 0x10), BIGINT(-1, 0x0A,0xAB,0xBC) },
    { BIGINT(-1, 0x10), BIGINT(1, 0x20), BIGINT(1, 0x00) },
    //signed remainder
    { BIGINT(1, 0x11), BIGINT(1, 0x02), BIGINT(1, 0x08), BIGINT(1, 0x01) },
    { BIGINT(-1, 0x11), BIGINT(1, 0x02), BIGINT(-1, 0x08), BIGINT(-1, 0x01) },
    { BIGINT(1, 0x11), BIGINT(-1, 0x02), BIGINT(-1, 0x08), BIGINT(1, 0x01) },
    { BIGINT(-1, 0x11), BIGINT(-1, 0x02), BIGINT(1, 0x08), BIGINT(-1, 0x01) },
    { BIGINT(-1, 0x10), BIGINT(1, 0x02), BIGINT(-1, 0x08), BIGINT(1, 0x00) },
    { BIGINT(-1, 0x10), BIGINT(1, 0x20), BIGINT(1, 0x00), BIGINT(-1, 0x10) },
    { BIGINT(-1, 0xAA,0xBB,0xCC), BIGINT(1, 0x10), BIGINT(-1, 0x0A,0xAB,0xBC), BIGINT(-1, 0x0C) },
    { BIGINT(1, 0x01,0x00,0x01), BIGINT(1, 0x01,0x00), BIGINT(1, 0x01,0x00), BIGINT(1, 0x01) },
    { BIGINT(-1, 0x01,0x00,0x01), BIGINT(1, 0x01,0x00), BIGINT(-1, 0x01,0x00), BIGINT(-1, 0x01) },
  };
  size_t len=ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_bigint_division tc=cases[i];
    bigint_t *remainder=NULL;
    bigint_t *quotient =div_bigint(&tc.dividend,&tc.divisor,&remainder);
    char *dividend_str =bigint_to_decimal_str(&tc.dividend);
    char *divisor_str =bigint_to_decimal_str(&tc.divisor);
    char *quotient_str =bigint_to_decimal_str(quotient);
    char *remainder_str =bigint_to_decimal_str(remainder);
    printf("case=%d %s÷%s=%s, remainder=%s\n",i,dividend_str,divisor_str,quotient_str,remainder_str);
    TEST_ASSERT_EQUAL_INT(tc.quotient.sign,quotient->sign);
    TEST_ASSERT_EQUAL_INT(tc.quotient.length,quotient->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.quotient.data,quotient->data,tc.quotient.length);
    if(tc.remainder.length!=0){
      TEST_ASSERT_EQUAL_INT(tc.remainder.sign,remainder->sign);
      TEST_ASSERT_EQUAL_INT(tc.remainder.length,remainder->length);
      TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.remainder.data,remainder->data,tc.remainder.length);
    }
  }
}

static void test_shift_left_bigint(void)
{
  test_case_bigint_bit_shift cases[] = {
    { BIGINT(NON_NEGATIVE,0xAA,0x12,0xFE,0x01),3,BIGINT(NON_NEGATIVE,0x05,0x50,0x97,0xF0,0x08) },
    { BIGINT(NON_NEGATIVE,0x01,0x02),1,BIGINT(NON_NEGATIVE,0x02,0x04) },
    { BIGINT(NON_NEGATIVE,0xFF, 0xFF, 0xFF),1,BIGINT(NON_NEGATIVE,0x01, 0xFF, 0xFF, 0xFE) },
    { BIGINT(NON_NEGATIVE,0xFF, 0xFF, 0xFF),0,BIGINT(NON_NEGATIVE, 0xFF, 0xFF, 0xFF) },
    { BIGINT(NON_NEGATIVE,0x80, 0x00),7,BIGINT(NON_NEGATIVE, 0x40, 0x00, 0x00) },
    { BIGINT(NON_NEGATIVE,0x80, 0x00),14,BIGINT(NON_NEGATIVE, 0x20, 0x00, 0x00,0x00) },
    { BIGINT(NON_NEGATIVE,0xFF),7,BIGINT(NON_NEGATIVE, 0x7F, 0x80) },
  };
  size_t len=ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_bigint_bit_shift tc=cases[i];
    bigint_t *result =shift_left_bigint(&tc.num1,tc.bits);
    char *strnum1 =bigint_to_decimal_str(&tc.num1);
    char *strres =bigint_to_decimal_str(result);
    printf("%s<<%d=%s\n",strnum1,tc.bits,strres);
    TEST_ASSERT_EQUAL_INT(tc.result.length,result->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.result.data,result->data,tc.result.length);
  }
}

static void test_shift_right_bigint(void)
{
  test_case_bigint_bit_shift cases[] = {
    { BIGINT(NON_NEGATIVE,0xAA,0x12,0xFE,0x01),3, BIGINT(NON_NEGATIVE,0x15,0x42,0x5F,0xC0) },
    { BIGINT(NON_NEGATIVE,0x02,0x04),1, BIGINT(NON_NEGATIVE,0x01,0x02) },
    { BIGINT(NON_NEGATIVE,0xFF,0xFF,0xFF),1, BIGINT(NON_NEGATIVE,0x7F,0xFF,0xFF) },
    { BIGINT(NON_NEGATIVE,0xFF,0xFF,0xFF),0, BIGINT(NON_NEGATIVE,0xFF,0xFF,0xFF) },
    { BIGINT(NON_NEGATIVE,0x12,0x34,0x56),8, BIGINT(NON_NEGATIVE,0x12,0x34) },
    { BIGINT(NON_NEGATIVE,0x12,0x34,0x56),12, BIGINT(NON_NEGATIVE,0x01,0x23) },
    { BIGINT(NON_NEGATIVE,0x80,0x00),1, BIGINT(NON_NEGATIVE,0x40,0x00) },
    { BIGINT(NON_NEGATIVE,0x80,0x00),8, BIGINT(NON_NEGATIVE,0x80) },
    { BIGINT(NON_NEGATIVE,0x01,0x00),16, BIGINT(NON_NEGATIVE,0x00) },
    { BIGINT(NON_NEGATIVE,0xFF,0xFF),32, BIGINT(NON_NEGATIVE,0x00) },
    { BIGINT(NON_NEGATIVE,0xFF),1, BIGINT(NON_NEGATIVE,0x7F) },
    { BIGINT(NON_NEGATIVE,0xFF),7, BIGINT(NON_NEGATIVE,0x01) },
    { BIGINT(NON_NEGATIVE,0xFF),8, BIGINT(NON_NEGATIVE,0x00) },
    { BIGINT(NON_NEGATIVE,0x01,0x00),1, BIGINT(NON_NEGATIVE,0x00,0x80) },
    { BIGINT(NON_NEGATIVE,0x03,0xFF),1, BIGINT(NON_NEGATIVE,0x01,0xFF) },
  };
  size_t len=ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_bigint_bit_shift tc=cases[i];
    bigint_t *result =shift_right_bigint(&tc.num1,tc.bits);
    char *strnum1 =bigint_to_decimal_str(&tc.num1);
    char *strres =bigint_to_decimal_str(result);
    printf("%s>>%d=%s\n",strnum1,tc.bits,strres);
    TEST_ASSERT_EQUAL_INT(tc.result.length,result->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.result.data,result->data,tc.result.length);
  }
}

static void test_mod_bigint(void)
{
  test_case_bigint_two_operands cases[] = {
    { BIGINT(1, 0x00), BIGINT(1, 0x11), BIGINT(1, 0x00) }, // 0 % 17 = 0
    { BIGINT(1, 0x11), BIGINT(1, 0x11), BIGINT(1, 0x00) }, // 17 % 17 = 0
    { BIGINT(1, 0x12), BIGINT(1, 0x11), BIGINT(1, 0x01) }, // 18 % 17 = 1
    { BIGINT(1, 0x10), BIGINT(1, 0x11), BIGINT(1, 0x10) }, // 16 % 17 = 16
    { BIGINT(1, 0x05), BIGINT(1, 0x02), BIGINT(1, 0x01) }, // 5 % 2 = 1
    { BIGINT(1, 0x06), BIGINT(1, 0x03), BIGINT(1, 0x00) }, // 6 % 3 = 0
    { BIGINT(1, 0x07), BIGINT(1, 0x03), BIGINT(1, 0x01) }, // 7 % 3 = 1
    { BIGINT(1, 0x01,0x00), BIGINT(1, 0x10), BIGINT(1, 0x00) }, // 256 % 16 = 0
    { BIGINT(1, 0x01,0xFF), BIGINT(1, 0x10), BIGINT(1, 0x0F) }, // 511 % 16 = 15
    { BIGINT(1, 0xFF,0xFF), BIGINT(1, 0xFF), BIGINT(1, 0x00) },
    { BIGINT(1, 0xFF,0xFF), BIGINT(1, 0xFE), BIGINT(1, 0x03) },
    { BIGINT(1, 0x12,0x34,0x56,0x78), BIGINT(1, 0xFF), BIGINT(1, 0x15) },
    { BIGINT(1, 0xAB,0xCD,0xEF,0x01), BIGINT(1, 0x0F), BIGINT(1, 0x01) },
    { BIGINT(1, 0x05), BIGINT(1, 0x10), BIGINT(1, 0x05) }, // 5 % 16 = 5
    { BIGINT(1, 0x01,0x00), BIGINT(1, 0x02,0x00), BIGINT(1, 0x01,0x00) }, // 256 % 512 = 256
    { BIGINT(NEGATIVE, 0x01), BIGINT(1, 0x11), BIGINT(1, 0x10) }, // -1 % 17 = 16
    { BIGINT(NEGATIVE, 0x12), BIGINT(1, 0x11), BIGINT(1, 0x10) }, // -18 % 17 = 16
    { BIGINT(NEGATIVE, 0x11), BIGINT(1, 0x11), BIGINT(1, 0x00) }, // -17 % 17 = 0
    { BIGINT(NEGATIVE, 0x01,0x00), BIGINT(1, 0x11), BIGINT(1, 0x10) }, // -256 % 17 = 16
    { BIGINT(1, 0x12,0x34), BIGINT(1, 0x10), BIGINT(1, 0x04) }, // mod 16
    { BIGINT(1, 0xAB,0xCD), BIGINT(1, 0x01,0x00), BIGINT(1, 0xCD) }, // mod 256
    { BIGINT(1, 0xFF,0xFF,0xFF,0xFF), BIGINT(1, 0xFF,0xFF), BIGINT(1, 0x00) },
    { BIGINT(1, 0x01,0x00,0x00), BIGINT(1, 0xFF,0xFF), BIGINT(1, 0x01) },
    { BIGINT(1, 3), BIGINT(1, 17), BIGINT(1, 3) },
    { BIGINT(1, 18), BIGINT(1, 17), BIGINT(1, 1) },
    { BIGINT(NEGATIVE, 1), BIGINT(1, 17), BIGINT(1, 16) },
    { BIGINT(NEGATIVE, 20), BIGINT(1, 17), BIGINT(1, 14) },
  };
  size_t len=ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_bigint_two_operands tc=cases[i];
    bigint_t *result =mod_bigint(&tc.num1,&tc.num2);
    char *strnum1 =bigint_to_decimal_str(&tc.num1);
    char *strnum2 =bigint_to_decimal_str(&tc.num2);
    char *strres =bigint_to_decimal_str(result);
    printf("%sx%s=%s\n",strnum1,strnum2,strres);
    TEST_ASSERT_EQUAL_INT(tc.result.length,result->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.result.data,result->data,tc.result.length);
    TEST_ASSERT_EQUAL_INT(tc.result.sign,result->sign);
  }
}

static void test_gcd(void)
{
  test_case_gcd cases[] = {
    {BIGINT(1,48),BIGINT(1,18),BIGINT(1,6)},
    {BIGINT(1,101), BIGINT(1,10), BIGINT(1,1)},
    {BIGINT(1,0), BIGINT(1,5), BIGINT(1,5)},
    {BIGINT(1,5), BIGINT(1,0), BIGINT(1,5)},
    {BIGINT(1,1), BIGINT(1,1), BIGINT(1,1)},
    {BIGINT(1,7), BIGINT(1,1), BIGINT(1,1)},
    {BIGINT(1,37), BIGINT(1,11), BIGINT(1,1)},
    {BIGINT(1,121), BIGINT(1,11), BIGINT(1,11)},
    {BIGINT(1,0x01,0x0E), BIGINT(1,0xC0), BIGINT(1,6)},
    {BIGINT(NON_NEGATIVE,0x05,0x21), BIGINT(NON_NEGATIVE,0x02,0xc3), BIGINT(NON_NEGATIVE,0x65)},
    {BIGINT(NON_NEGATIVE,0X01,0XE2,0X40), BIGINT(NON_NEGATIVE,0X03,0X15), BIGINT(NON_NEGATIVE,0X3)},
  };
  size_t len = ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_gcd tc=cases[i];
    bigint_t *result=gcd_bigint(&tc.dividend,&tc.divisor);
    printf("case=%dP\n",i);
    TEST_ASSERT_EQUAL_INT(tc.expected.length,result->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.expected.data,result->data,tc.expected.length);
  }
}

static void test_xgcd(void)
{
  test_case_xgcd cases[] = {
		{BIGINT(1,0x07,0x5B,0xCD,0x15),BIGINT(1,0x3B,0x9A,0xCA,0x07), BIGINT(1,1),BIGINT(1,0x01,0x1C,0x53,0x44), BIGINT(NEGATIVE,0x23,0x1A,0x15) },
    {BIGINT(1,252),BIGINT(1,198),BIGINT(1,18),BIGINT(1,4),BIGINT(NEGATIVE,5)},
    {BIGINT(1,30),BIGINT(1,20),BIGINT(1,10),BIGINT(1,1),BIGINT(NEGATIVE,1)},
    {BIGINT(1,35), BIGINT(1,15) ,BIGINT(1,5), BIGINT(1,1), BIGINT(NEGATIVE,2)},
    {BIGINT(1,101), BIGINT(1,23),BIGINT(1,1), BIGINT(NEGATIVE,5), BIGINT(1,22)},
    {BIGINT(1,17), BIGINT(1,31),BIGINT(1,1), BIGINT(1,11), BIGINT(NEGATIVE,6)},
    {BIGINT(1,20), BIGINT(1,30),BIGINT(1,10), BIGINT(NEGATIVE,1), BIGINT(1,1)},
    {BIGINT(1,7), BIGINT(1,13),BIGINT(1,1), BIGINT(1,2), BIGINT(NEGATIVE,1)},
    {BIGINT(1,3), BIGINT(1,11),BIGINT(1,1), BIGINT(1,4), BIGINT(NEGATIVE,1)},
    {BIGINT(1,19), BIGINT(1,121),BIGINT(1,1), BIGINT(1,51), BIGINT(NEGATIVE,8)},
    {BIGINT(1,10), BIGINT(1,5),BIGINT(1,5), BIGINT(1,0), BIGINT(1,1)},
    {BIGINT(1,5), BIGINT(1,10),BIGINT(1,5), BIGINT(1,1), BIGINT(1,0)},
    {BIGINT(1,0), BIGINT(1,5),BIGINT(1,5), BIGINT(1,0), BIGINT(1,1)},
    {BIGINT(1,5), BIGINT(1,0),BIGINT(1,5), BIGINT(1,1), BIGINT(1,0)},
    {BIGINT(NEGATIVE,30), BIGINT(1,20),BIGINT(1,10), BIGINT(NEGATIVE,1), BIGINT(NEGATIVE,1)},
    {BIGINT(1,30), BIGINT(NEGATIVE,20),BIGINT(1,10), BIGINT(1,1), BIGINT(1,1)},
    {BIGINT(NEGATIVE,30), BIGINT(NEGATIVE,20),BIGINT(1,10), BIGINT(NEGATIVE,1), BIGINT(1,1)},
    {BIGINT(1,240), BIGINT(1,46),BIGINT(1,2), BIGINT(NEGATIVE,9), BIGINT(1,47)},
    {BIGINT(1,0x10,0x00), BIGINT(1,0x04,0x00),BIGINT(1,0x04,0x00), BIGINT(1,0), BIGINT(1,1)},
    {BIGINT(1,0x01,0xE2,0x40), BIGINT(1,0x1E,0xD2),BIGINT(1,6), BIGINT(NEGATIVE,0x02,0x89), BIGINT(1,0x27,0xAB)},
  };
  size_t len = ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_xgcd tc=cases[i];
    xgcd_result_t result=xgcd_bigint(&tc.a,&tc.b);
    printf("case=%dP\n",i);
    TEST_ASSERT_EQUAL_INT(tc.g.length,result.g->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.g.data,result.g->data,tc.g.length);
    TEST_ASSERT_EQUAL_INT(result.g->sign,tc.g.sign);

    TEST_ASSERT_EQUAL_INT(tc.x.length,result.x->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.x.data,result.x->data,tc.x.length);
    TEST_ASSERT_EQUAL_INT(result.x->sign,tc.x.sign);

    TEST_ASSERT_EQUAL_INT(tc.y.length,result.y->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.y.data,result.y->data,tc.y.length);
    TEST_ASSERT_EQUAL_INT(result.y->sign,tc.y.sign);
  }
}

static void test_mod_inverse(void)
{
  test_case_modinv cases[] = {
    {BIGINT(0,3),BIGINT(1,17),BIGINT(1,6)},
    {BIGINT(1,5),BIGINT(1,17),BIGINT(1,7)},
    {BIGINT(1,8),BIGINT(1,19),BIGINT(1,12)},
    {BIGINT(1,3),BIGINT(1,7),BIGINT(1,5)},
    {BIGINT(1,2),BIGINT(1,17),BIGINT(1,9)},
    {BIGINT(1,3),BIGINT(1,11),BIGINT(1,4)},
    {BIGINT(1,6),BIGINT(1,15),BIGINT(0,0)},
    {BIGINT(1,6),BIGINT(1,18),BIGINT(0,0)},
    {BIGINT(1,4),BIGINT(1,16),BIGINT(0,0)},
    {BIGINT(1,0),BIGINT(1,17),BIGINT(0,0)},
    {BIGINT(1,17),BIGINT(1,17),BIGINT(0,0)},
    {BIGINT(1,1),BIGINT(1,17),BIGINT(1,1)},
    {BIGINT(NEGATIVE,3),BIGINT(1,11),BIGINT(1,7)},
    {BIGINT(NEGATIVE,3),BIGINT(1,17),BIGINT(1,11)},
    {BIGINT(NEGATIVE,5),BIGINT(1,17),BIGINT(1,10)},
    {BIGINT(1,0x07,0x5B,0xCD,0x15),BIGINT(1,0x3B,0x9A,0xCA,0x07),BIGINT(1,0x01,0x1C,0x53,0x44)},
  };
  size_t len = ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_modinv tc=cases[i];
    bigint_t *result=mod_inverse(&tc.num,&tc.divisor);
    printf("case=%dP\n",i);
		if(tc.expected.sign!=0) {
			TEST_ASSERT_EQUAL_INT(tc.expected.length,result->length);
			TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.expected.data,result->data,tc.expected.length);
		}else {
			TEST_ASSERT_NULL(result);
		}
  }
}


int main(void)
{
  UNITY_BEGIN();
	RUN_TEST(test_bigint_create);
	RUN_TEST(test_mul_bigint);
	RUN_TEST(test_add_bigint);
	RUN_TEST(test_decimal_to_bigint);
	RUN_TEST(test_sub_bigint);
	RUN_TEST(test_compare_bigint);
	RUN_TEST(test_bigint_to_decimal);
	RUN_TEST(test_div_bigint);
	RUN_TEST(test_shift_left_bigint);
	RUN_TEST(test_shift_right_bigint);
	RUN_TEST(test_mod_bigint);
	RUN_TEST(test_gcd);
	RUN_TEST(test_xgcd);
	RUN_TEST(test_mod_inverse);
  return UNITY_END();
}
