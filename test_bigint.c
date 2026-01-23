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
		{(uint8_t[]){0xFA,0xCE},2,"-1330"},
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
  return UNITY_END();
}
