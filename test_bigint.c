#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bigint.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))
#define BIGINT(result,...) {result,(uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__})}

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
} test_case_bigint_two_operand;

typedef struct {
  uint8_t *hex;
  size_t length;
  char *result;
} test_case_hex_to_decimal;

typedef struct {
  char *decimal;
  bigint_t bigint;
} test_case_decimal_to_hex;

typedef struct {
  char *x;
  char *y;
  int result;
} test_case_compare;

void setUp(void)
{
}

void tearDown(void)
{
}


static void test_zero(void)
{
	uint8_t buf[] = {0x00};
	size_t len=ARRAY_LEN(buf);
	bigint_t *bigint =create_bigint(buf,len);
	TEST_ASSERT_EQUAL(0,bigint->sign);
	TEST_ASSERT_EQUAL("0",bigint_to_decimal_str(bigint));
}

static void test_mul(void)
{
	test_case_mul cases[] = {
		{"5","16","80",10},
		{"7","16","112",10},
		{"12","16","192",10},
    {"12345678901234567890", "16", "197530862419753086240",10},
		{"5","53","361",7},
		{"7","8","38",16},
		//{"A","D","82",16},
	};
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_mul tc=cases[i];
		char *result =mul(tc.x,tc.y,tc.base);
		TEST_ASSERT_EQUAL_STRING(tc.result,result);
	}
}


static void test_mul_bigint(void)
{
  test_case_bigint_two_operand cases[] = {
    { BIGINT(1,0x05), BIGINT(1,0x10), BIGINT(1,0x50) },
    { BIGINT(1,0x07), BIGINT(1,0x10), BIGINT(1,0x70) },
    { BIGINT(1,0x0C), BIGINT(1,0x10), BIGINT(1,0xC0), },
    { BIGINT(1,0x05), BIGINT(1,0x35), BIGINT(1,0x01,0x09) },
    { BIGINT(1,0x07), BIGINT(1,0x08), BIGINT(1,0x38) },
    { BIGINT(1,0xFA,0xCA), BIGINT(1,0x02,0x03), BIGINT(1, 0x01,0xF8,0x84,0x5E) },
  };
  size_t len=ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_bigint_two_operand tc=cases[i];
    bigint_t *result =mul_bigint(&tc.num1,&tc.num2);
    TEST_ASSERT_EQUAL_INT(tc.result.length,result->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.result.data,result->data,tc.result.length);
  }
}


static void test_hex_to_decimal(void)
{
	test_case_hex_to_decimal cases[] = {
		{(uint8_t[]){0xFA,0xCE},2,"-1330"},
		{(uint8_t[]){0x00,0x87},2,"135"},
		{(uint8_t[]){0xFF,0xFF,0xFF,0xFF},4,"-1"},
		{(uint8_t[]){0x01,0x00,0x00,0x00,0x00},5,"4294967296"},
		{(uint8_t[]){0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},8,"-1"},
		{(uint8_t[]){0xFF},1,"-1"},
		{(uint8_t[]){0xFF,0x00},2,"-256"},
		{(uint8_t[]){0x80},1,"-128"},
		{(uint8_t[]){0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},9,"-2361183241434822606848"},
	};
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_hex_to_decimal tc=cases[i];
		char *result =hex_to_decimal_str(tc.hex,tc.length);
		TEST_ASSERT_EQUAL_STRING(tc.result,result);
	}
}


static void test_decimal_to_hex(void)
{
	test_case_decimal_to_hex cases[] = {
		{"135",(bigint_t){1,(uint8_t[]){0x00,0x87},2}},
		//{"-1330",(bigint_t){1,(uint8_t[]){0xFA,0xCE},2}},
		//{"-1",(bigint_t){1,(uint8_t[]){0xFF,0xFF,0xFF,0xFF},4}},
		//{"4294967296",(bigint_t){1,(uint8_t[]){0x01,0x00,0x00,0x00,0x00},5}},
		//{"-1",(bigint_t){1,(uint8_t[]){0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},8}},
		//{"-1",(bigint_t){1,(uint8_t[]){0xFF},1}},
		//{"-256",(bigint_t){1,(uint8_t[]){0xFF,0x00},2}},
		//{"-128",(bigint_t){1,(uint8_t[]){0x80},1}},
		//{"-2361183241434822606848",(bigint_t){1,(uint8_t[]){0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},9}},
	};
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_decimal_to_hex tc=cases[i];
		bigint_t *bi =bigint_from_decimal_str(tc.decimal);
		TEST_ASSERT_EQUAL_INT(tc.bigint.length,bi->length);
		TEST_ASSERT_EQUAL_STRING(tc.bigint.data,bi->data);
	}
}


static void test_add(void)
{
	test_case_mul cases[] = {
		{"5","16","21",10},
		{"7","16","23",10},
		{"12","16","28",10},
		{"1250","25","1275",10},
		{"42","70","112",10},
    {"999", "1", "1000",10},
    {"18446744073709551615", "15", "18446744073709551630",10},
	};
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_mul tc=cases[i];
		char *result =add(tc.x,tc.y,tc.base);
		TEST_ASSERT_EQUAL_STRING(tc.result,result);
	}
}

static void test_add_bigint(void)
{
  test_case_bigint_two_operand cases[] = {
    { BIGINT(1,0x05), BIGINT(1,0x10), BIGINT(1,0x15) },
    { BIGINT(1,0x07), BIGINT(1,0x10), BIGINT(1,0x17) },
    { BIGINT(1,0x0C), BIGINT(1,0x10), BIGINT(1,0x1C) },
    { BIGINT(1,0x04,0xE2), BIGINT(1,0x19), BIGINT(1,0x04,0xFB) },
    { BIGINT(1,0x2A), BIGINT(1,0x46), BIGINT(1,0x70) },
    { BIGINT(1,0x03, 0xE7), BIGINT(1,0x01), BIGINT(1,0x03, 0xE8) },
    { BIGINT(1,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF), BIGINT(1,0x0F), BIGINT(1,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0E), }
  };
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_bigint_two_operand tc=cases[i];
    bigint_t *result =add_bigint(&tc.num1,&tc.num2);
    TEST_ASSERT_EQUAL_INT(tc.result.length,result->length);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tc.result.data,result->data,tc.result.length);
	}
}

static void test_subtract(void)
{
  test_case_mul cases[] = {
    {"5", "3", "2"},
    {"10", "4", "6"},
    {"100", "50", "50"},
    {"163", "57", "106"},
    {"163", "67", "96"},
    {"10", "1", "9"},
    {"100", "1", "99"},
    {"1000", "1", "999"},
    {"1000", "1", "999"},
    {"10000", "1", "9999"},
    {"100000", "1", "99999"},
    {"1000", "999", "1"},
    {"10000", "9999", "1"},
    {"100000", "99999", "1"},
    {"1000000", "999999", "1"},
    {"123456789012345678901234567890", "123456789012345678901234567889", "1"},
    {"3", "5", "-2"},
    {"4", "10", "-6"},
    {"50", "100", "-50"},
  };

  size_t len = ARRAY_LEN(cases);
  for (int i = 0; i < len; i++) {
    test_case_mul tc = cases[i];
    char *result = sub(tc.x, tc.y);
    TEST_ASSERT_EQUAL_STRING(tc.result, result);
  }
}

static void test_compare(void)
{
	test_case_compare cases[] = {
		{"5","16",-1},
		{"7","16",-1},
		{"1250","25",1},
	};
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_compare tc=cases[i];
    char msg[40];
    snprintf(msg,20,"case=%d\n",i);
		int result =compare(tc.x,tc.y);
		TEST_ASSERT_EQUAL_MESSAGE(tc.result,result,msg);
	}
}


int main(void)
{
  UNITY_BEGIN();
	RUN_TEST(test_zero);
	RUN_TEST(test_mul);
	RUN_TEST(test_add);
	RUN_TEST(test_hex_to_decimal);
	RUN_TEST(test_subtract);
	RUN_TEST(test_compare);
	RUN_TEST(test_mul_bigint);
	RUN_TEST(test_add_bigint);
	//RUN_TEST(test_decimal_to_hex);
  return UNITY_END();
}
