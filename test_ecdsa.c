#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ecdsa.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))

void setUp(void)
{
}

void tearDown(void)
{
}

typedef struct {
  ecdsa_point_t p;
  int times;
  ecdsa_point_t result;
} test_case_ec_times;

typedef struct {
  int num;
  int divisor;
  int expected;
} test_case_modinv;

typedef struct {
  int dividend;
  int divisor;
  int expected;
} test_case_gcd;

typedef struct {
  int a;
  int b;
  int g;
  int x;
  int y;
} test_case_xgcd;

static void test_times_point(void)
{
  ecdsa_params_t params={
    .p=17,
    .a=2,
    .b=2
  };
  test_case_ec_times cases[] = {
    {(ecdsa_point_t){5,1},0,(ecdsa_point_t){.is_infinity=true}},
    {(ecdsa_point_t){5,1},1,(ecdsa_point_t){5, 1}},
    {(ecdsa_point_t){5,1},2,(ecdsa_point_t){6, 3}},
    {(ecdsa_point_t){5,1},3,(ecdsa_point_t){10, 6}},
    {(ecdsa_point_t){5,1},4,(ecdsa_point_t){3, 1}},
    {(ecdsa_point_t){5,1},5,(ecdsa_point_t){9, 16}},
    {(ecdsa_point_t){5,1},6,(ecdsa_point_t){16, 13}},
    {(ecdsa_point_t){5,1},7,(ecdsa_point_t){0, 6}},
    {(ecdsa_point_t){5,1},8,(ecdsa_point_t){13, 7}},
    {(ecdsa_point_t){5,1},9,(ecdsa_point_t){7, 6}},
    {(ecdsa_point_t){5,1},10,(ecdsa_point_t){7, 11}},
    {(ecdsa_point_t){5,1},11,(ecdsa_point_t){13, 10}},
    {(ecdsa_point_t){5,1},12,(ecdsa_point_t){0, 11}},
    {(ecdsa_point_t){5,1},13,(ecdsa_point_t){16,4}},
    {(ecdsa_point_t){5,1},14,(ecdsa_point_t){9,1}},
    {(ecdsa_point_t){5,1},15,(ecdsa_point_t){3,16}},
    {(ecdsa_point_t){5,1},16,(ecdsa_point_t){10,11}},
    {(ecdsa_point_t){5,1},19,(ecdsa_point_t){.is_infinity=true}},
  };
  size_t len = ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_ec_times tc=cases[i];
    ecdsa_point_t res=ecdsa_point_times(params,tc.times,tc.p);
    printf("case=%dP\n",i);
    TEST_ASSERT_EQUAL_INT(tc.result.x,res.x);
    TEST_ASSERT_EQUAL_INT(tc.result.y,res.y);
  }
}

static void test_add_point(void)
{
  ecdsa_params_t params={
    .p=17,
    .a=2,
    .b=2
  };
  ecdsa_point_t p1={5,1};
  ecdsa_point_t p2={6,3};
  ecdsa_point_t res=ecdsa_point_add(params,p1,p2);
  TEST_ASSERT_EQUAL_INT(10,res.x);
  TEST_ASSERT_EQUAL_INT(6,res.y);
  ecdsa_point_t p3={6,3};
  ecdsa_point_t p4={3,1};
  ecdsa_point_t res1=ecdsa_point_add(params,p3,p4);
  TEST_ASSERT_EQUAL_INT(16,res1.x);
  TEST_ASSERT_EQUAL_INT(13,res1.y);
  ecdsa_point_t p5={9,16};
  ecdsa_point_t p6={5,16};
  ecdsa_point_t res2=ecdsa_point_add(params,p5,p6);
  TEST_ASSERT_EQUAL_INT(3,res2.x);
  TEST_ASSERT_EQUAL_INT(1,res2.y);
}

static void test_times_and_add_consistency(void)
{
  ecdsa_params_t params={
    .p=17,
    .a=2,
    .b=2
  };
  ecdsa_point_t p1={5,1};
  ecdsa_point_t p3 = ecdsa_point_times(params, 3, p1);
  ecdsa_point_t p5 = ecdsa_point_times(params, 5, p1);
  ecdsa_point_t p8 = ecdsa_point_times(params, 8, p1);
  ecdsa_point_t sum = ecdsa_point_add(params, p3, p5);
  TEST_ASSERT_EQUAL(p8.x, sum.x);
  TEST_ASSERT_EQUAL(p8.y, sum.y);
}

static void test_signature_verify(void)
{
  ecdsa_params_t params={
    .p=17,
    .a=2,
    .b=2,
    .n=19,
    .g={5,1},
  };
  int z=11;
  ecdsa_signature_t sig={10,8};
  ecdsa_point_t q={0,6};
  bool valid=ecdsa_signature_verify(params,sig,z,q);
  TEST_ASSERT_TRUE(valid);
}

static void test_scalar_mul_identity(void)
{
  ecdsa_params_t params = {
    .p = 17,
    .a = 2,
    .b = 2
  };
  ecdsa_point_t p1 = {5, 1};
  ecdsa_point_t res = ecdsa_point_times(params, 0, p1);
  TEST_ASSERT_TRUE(res.is_infinity);
}
static void test_addition_infinity(void)
{
  ecdsa_params_t params = {
    .p = 17,
    .a = 2,
    .b = 2
  };
  ecdsa_point_t p1 = {5, 1};
  ecdsa_point_t p3  = ecdsa_point_times(params, 3, p1);
  ecdsa_point_t p16 = ecdsa_point_times(params, 16, p1);
  ecdsa_point_t res = ecdsa_point_add(params, p16, p3);
  TEST_ASSERT_TRUE(res.is_infinity);
}

static void test_mod_inverse(void)
{
  test_case_modinv cases[] = {
    {3,17,6},
    {5,17,7},
    {8,19,12},
    {3,7,5},
    {2,17,9},
    {3,11,4},
    {-3,11,7},
    {123456789,1000000007,18633540},
    {6,15,0},
    {6,18,0},
    {4,16,0},
    {0,17,0},
    {-3,17,11},
    {-5,17,10},
    {17,17,0},
    {1,17,1},
  };
  size_t len = ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_modinv tc=cases[i];
    int result=ecdsa_mod_inverse(tc.num,tc.divisor);
    printf("case=%dP\n",i);
    TEST_ASSERT_EQUAL_INT(tc.expected,result);
  }
}

static void test_ecdsa_xgcd(void)
{
  test_case_xgcd cases[] = {
		{123456789,1000000007, 1,18633540, -2300437 },
    {252,198,18,4,-5},
    {30,20,10,1,-1},
    {35, 15 ,5, 1, -2},
    {101, 23,1, -5, 22},
    {17, 31,1, 11, -6},
    {20, 30,10, -1, 1},
    {7, 13,1, 2, -1},
    {3, 11,1, 4, -1},
    {19, 121,1, 51, -8},
    {10, 5,5, 0, 1},
    {5, 10,5, 1, 0},
    {0, 5,5, 0, 1},
    {5, 0,5, 1, 0},
    {-30, 20,10, -1, -1},
    {30, -20,10, 1, 1},
    {-30, -20,10, -1, 1},
    {240, 46,2, -9, 47},
    {4096, 1024,1024, 0, 1},
    {123456, 7890,6, -649, 10155},
  };
  size_t len = ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_xgcd tc=cases[i];
    xgcd_result_t result=ecdsa_xgcd(tc.a,tc.b);
    printf("case=%dP\n",i);
    TEST_ASSERT_EQUAL_INT(tc.g,result.g);
    TEST_ASSERT_EQUAL_INT(tc.x,result.x);
    TEST_ASSERT_EQUAL_INT(tc.y,result.y);
  }
}


int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_times_point);
  RUN_TEST(test_add_point);
  RUN_TEST(test_signature_verify);
  RUN_TEST(test_times_and_add_consistency);
  RUN_TEST(test_scalar_mul_identity);
  RUN_TEST(test_addition_infinity);
  RUN_TEST(test_mod_inverse);
  RUN_TEST(test_ecdsa_xgcd);
  return UNITY_END();
}
