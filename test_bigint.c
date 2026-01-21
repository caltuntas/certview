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
  return UNITY_END();
}
