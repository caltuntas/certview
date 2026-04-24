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

static void test_verify(void)
{
  ecdsa_params_t params={
    .p=17,
    .a=2,
    .b=2,
    .n=19,
    .z=11,
  };
  ecdsa_point_t p1={10,8};
  ecdsa_point_t g={5,1};
  ecdsa_point_t q={0,6};
  bool valid=ecdsa_verify(params,p1,g,q);
  TEST_ASSERT_TRUE(valid);
}

static void test_mod(void)
{
  int results[][3]={
    {3,17,3},
    {18,17,1},
    {-1,17,16},
    {-20,17,14},
  };
  size_t len = ARRAY_LEN(results);
  for(int i=0; i<len; i++){
    int *row=results[i];
    int res=ecdsa_mod(row[0],row[1]);
    TEST_ASSERT_EQUAL_INT(row[2],res);
  }
}

static void test_mod_inverse(void)
{
  int results[][3]={
    {3,7,5},
    {2,17,9},
  };
  size_t len = ARRAY_LEN(results);
  for(int i=0; i<len; i++){
    int *row=results[i];
    int res=ecdsa_mod_inverse(row[0],row[1]);
    TEST_ASSERT_EQUAL_INT(row[2],res);
  }
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

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_times_point);
  RUN_TEST(test_add_point);
  RUN_TEST(test_mod);
  RUN_TEST(test_mod_inverse);
  RUN_TEST(test_verify);
  RUN_TEST(test_times_and_add_consistency);
  RUN_TEST(test_scalar_mul_identity);
  RUN_TEST(test_addition_infinity);
  return UNITY_END();
}
