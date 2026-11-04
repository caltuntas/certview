#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "integer.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))

typedef struct {
  int num1;
  int num2;
  bool success;
  int result;
} test_case_int_two_operands;

typedef struct {
	size_t num1;
	size_t num2;
	bool success;
	size_t result;
} test_case_sizet;

void setUp(void)
{
}

void tearDown(void)
{
}

static void test_integer_add_int_safe(void)
{
  test_case_int_two_operands cases[] = {
    { 10,20,true,30},
    { -10,-20,true,-30},
    { 15,-15,true,0},
    { 50,-20,true,30},
    { -50,20,true,-30},
    { 50,0,true,50},
    { 0,50,true,50},
    { 0,0,true,0},
    { INT_MAX,0,true,INT_MAX},
    { INT_MIN,0,true,INT_MIN},
    { (INT_MAX-1),1,true,INT_MAX},
    { (INT_MIN+1),-1,true,INT_MIN},
    { INT_MAX,1,false, 0},
    { INT_MAX,INT_MAX,false, 0},
    { (INT_MAX/2)+1,(INT_MAX/2)+1,false,0},
    { INT_MIN,-1,false, 0},
    { INT_MIN,INT_MIN,false, 0},
    { (INT_MIN/2)-1,(INT_MIN/2)-1,false, 0},
  };
  size_t len=ARRAY_LEN(cases);
  for(size_t i=0; i<len; i++){
    test_case_int_two_operands tc=cases[i];
    int old_res=-12345;
    int res=old_res;
    bool success = integer_add_int_safe(tc.num1,tc.num2,&res);
    printf("case=%zu\n",i);
    TEST_ASSERT_EQUAL_INT(tc.success,success);
    if(success==true) {
      TEST_ASSERT_EQUAL_INT(tc.result,res);
    }else {
      TEST_ASSERT_EQUAL_INT(old_res,res);
    }
  }
}

static void test_integer_add_int_safe_null_pointer(void)
{
  bool null_res = integer_add_int_safe(10, 20, NULL);
  TEST_ASSERT_FALSE(null_res);
}

static void test_integer_add_sizet_safe(void)
{
	test_case_sizet cases[] = {
		{ 10, 20, true, 30 },
		{ 1024, 2048, true, 3072 },
		{ 0, 0, true, 0 },
		{ 50, 0, true, 50 },
		{ 0, 50, true, 50 },
		{ SIZE_MAX, 0, true, SIZE_MAX },
		{ SIZE_MAX - 1, 1, true, SIZE_MAX },
		{ SIZE_MAX - 100, 100, true, SIZE_MAX },
		{ SIZE_MAX, 1, false, 0 },
		{ SIZE_MAX, 100, false, 0 },
		{ SIZE_MAX, SIZE_MAX, false, 0 },
		{ SIZE_MAX - 16, 32, false, 0 },
		{ (SIZE_MAX / 2) + 1, (SIZE_MAX / 2) + 1, false, 0 }
	};
	size_t len = sizeof(cases) / sizeof(cases[0]);
	for (size_t i = 0; i < len; i++) {
		test_case_sizet tc = cases[i];
		size_t old_res = (size_t)0xDEADBEEF;
		size_t res = old_res;
		bool success = integer_add_sizet_safe(tc.num1, tc.num2, &res);
		printf("sizet_add_case=%zu\n", i);
		TEST_ASSERT_EQUAL_size_t(tc.success,success);
		if (success) {
			TEST_ASSERT_EQUAL_size_t(tc.result,res);
		} else {
			TEST_ASSERT_EQUAL_size_t(old_res, res);
		}
	}
}

static void test_integer_add_sizet_safe_null_pointer(void)
{
	bool null_res = integer_add_sizet_safe(10, 20, NULL);
	TEST_ASSERT_FALSE(null_res);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_integer_add_int_safe);
  RUN_TEST(test_integer_add_int_safe_null_pointer);
  RUN_TEST(test_integer_add_sizet_safe);
  RUN_TEST(test_integer_add_sizet_safe_null_pointer);
  return UNITY_END();
}
