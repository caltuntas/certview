#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bigint.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))

typedef struct {
  char *x;
  char *y;
  char *result;
} test_case_mul;

typedef struct {
  uint8_t *hex;
  size_t length;
  char *result;
} test_case_hex_to_decimal;

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
		{"5","16","80"},
		{"7","16","112"},
		{"12","16","192"},
    {"12345678901234567890", "16", "197530862419753086240"},
	};
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_mul tc=cases[i];
		char *result =mul(tc.x,tc.y);
		TEST_ASSERT_EQUAL_STRING(tc.result,result);
	}
}


static void test_hex_to_decimal(void)
{
	test_case_hex_to_decimal cases[] = {
		{(uint8_t[]){0xFA,0xCE},2,"64206"},
		{(uint8_t[]){0xFF,0xFF,0xFF,0xFF},4,"4294967295"},
		{(uint8_t[]){0x01,0x00,0x00,0x00,0x00},5,"4294967296"},
		{(uint8_t[]){0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},8,"18446744073709551615"},
	};
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_hex_to_decimal tc=cases[i];
		char *result =hex_to_decimal_str(tc.hex,tc.length);
		TEST_ASSERT_EQUAL_STRING(tc.result,result);
	}
}


static void test_add(void)
{
	test_case_mul cases[] = {
		{"5","16","21"},
		{"7","16","23"},
		{"12","16","28"},
		{"1250","25","1275"},
		{"42","70","112"},
    {"999", "1", "1000"},
    {"18446744073709551615", "15", "18446744073709551630"},
	};
	size_t len=ARRAY_LEN(cases);
	for(int i=0; i<len; i++){
		test_case_mul tc=cases[i];
		char *result =add(tc.x,tc.y);
		TEST_ASSERT_EQUAL_STRING(tc.result,result);
	}
}


int main(void)
{
  UNITY_BEGIN();
	RUN_TEST(test_zero);
	RUN_TEST(test_mul);
	RUN_TEST(test_add);
	RUN_TEST(test_hex_to_decimal);
  return UNITY_END();
}
