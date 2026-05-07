#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ecdsa.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))
#define BIGINT(sign,...) (bigint_t){sign,(uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__})}

void setUp(void)
{
}

void tearDown(void)
{
}

typedef struct {
  ecdsa_point_t p;
  bigint_t *times;
  ecdsa_point_t result;
} test_case_ec_times;

static void test_times_point(void)
{
  bigint_t p=BIGINT(1,17);
  bigint_t a=BIGINT(1,2);
  bigint_t b=BIGINT(1,2);
  ecdsa_params_t params={
    .p=&p,
    .a=&a,
    .b=&b
  };
  test_case_ec_times cases[] = {
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(0),(ecdsa_point_t){.is_infinity=true}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(1),(ecdsa_point_t){create_bigint_from_int(5), create_bigint_from_int(1)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(2),(ecdsa_point_t){create_bigint_from_int(6), create_bigint_from_int(3)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(3),(ecdsa_point_t){create_bigint_from_int(10), create_bigint_from_int(6)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(4),(ecdsa_point_t){create_bigint_from_int(3), create_bigint_from_int(1)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(5),(ecdsa_point_t){create_bigint_from_int(9), create_bigint_from_int(16)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(6),(ecdsa_point_t){create_bigint_from_int(16), create_bigint_from_int(13)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(7),(ecdsa_point_t){create_bigint_from_int(0), create_bigint_from_int(6)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(8),(ecdsa_point_t){create_bigint_from_int(13), create_bigint_from_int(7)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(9),(ecdsa_point_t){create_bigint_from_int(7), create_bigint_from_int(6)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(10),(ecdsa_point_t){create_bigint_from_int(7), create_bigint_from_int(11)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(11),(ecdsa_point_t){create_bigint_from_int(13), create_bigint_from_int(10)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(12),(ecdsa_point_t){create_bigint_from_int(0), create_bigint_from_int(11)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(13),(ecdsa_point_t){create_bigint_from_int(16),create_bigint_from_int(4)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(14),(ecdsa_point_t){create_bigint_from_int(9),create_bigint_from_int(1)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(15),(ecdsa_point_t){create_bigint_from_int(3),create_bigint_from_int(16)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(16),(ecdsa_point_t){create_bigint_from_int(10),create_bigint_from_int(11)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(19),(ecdsa_point_t){.is_infinity=true}},
  };
  size_t len = ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_ec_times tc=cases[i];
    ecdsa_point_t res=ecdsa_point_times(params,tc.times,tc.p);
    printf("case=%dP\n",i);
    if(tc.result.is_infinity){
      TEST_ASSERT_NULL(res.x);
      TEST_ASSERT_NULL(res.y);
      TEST_ASSERT_TRUE(res.is_infinity);
    } else {
      TEST_ASSERT_EQUAL_INT(tc.result.x->data[0],res.x->data[0]);
      TEST_ASSERT_EQUAL_INT(tc.result.y->data[0],res.y->data[0]);
    }
  }
}

static void test_add_point(void)
{
  bigint_t p=BIGINT(1,17);
  bigint_t a=BIGINT(1,2);
  bigint_t b=BIGINT(1,2);
  ecdsa_params_t params={
    .p=&p,
    .a=&a,
    .b=&b
  };
  ecdsa_point_t p1={create_bigint_from_int(5),create_bigint_from_int(1)};
  ecdsa_point_t p2={create_bigint_from_int(6),create_bigint_from_int(3)};
  ecdsa_point_t res=ecdsa_point_add(params,p1,p2);
  TEST_ASSERT_EQUAL_INT(10,res.x->data[0]);
  TEST_ASSERT_EQUAL_INT(6,res.y->data[0]);
  ecdsa_point_t p3={create_bigint_from_int(6),create_bigint_from_int(3)};
  ecdsa_point_t p4={create_bigint_from_int(3),create_bigint_from_int(1)};
  ecdsa_point_t res1=ecdsa_point_add(params,p3,p4);
  TEST_ASSERT_EQUAL_INT(16,res1.x->data[0]);
  TEST_ASSERT_EQUAL_INT(13,res1.y->data[0]);
  ecdsa_point_t p5={create_bigint_from_int(9),create_bigint_from_int(16)};
  ecdsa_point_t p6={create_bigint_from_int(5),create_bigint_from_int(16)};
  ecdsa_point_t res2=ecdsa_point_add(params,p5,p6);
  TEST_ASSERT_EQUAL_INT(3,res2.x->data[0]);
  TEST_ASSERT_EQUAL_INT(1,res2.y->data[0]);
}

static void test_times_and_add_consistency(void)
{
  bigint_t p=BIGINT(1,17);
  bigint_t a=BIGINT(1,2);
  bigint_t b=BIGINT(1,2);
  ecdsa_params_t params={
    .p=&p,
    .a=&a,
    .b=&b
  };
  ecdsa_point_t p1={create_bigint_from_int(5),create_bigint_from_int(1)};
  ecdsa_point_t p3 = ecdsa_point_times(params, create_bigint_from_int(3), p1);
  ecdsa_point_t p5 = ecdsa_point_times(params, create_bigint_from_int(5), p1);
  ecdsa_point_t p8 = ecdsa_point_times(params, create_bigint_from_int(8), p1);
  ecdsa_point_t sum = ecdsa_point_add(params, p3, p5);
  TEST_ASSERT_TRUE(compare_bigint(p8.x, sum.x)==0);
  TEST_ASSERT_TRUE(compare_bigint(p8.y, sum.y)==0);
}

static void test_signature_verify(void)
{
  ecdsa_params_t params={
    .p=create_bigint_from_int(17),
    .a=create_bigint_from_int(2),
    .b=create_bigint_from_int(2),
    .n=create_bigint_from_int(19),
    .g={create_bigint_from_int(5),create_bigint_from_int(1)},
  };
  bigint_t *z=create_bigint_from_int(11);
  ecdsa_signature_t sig={create_bigint_from_int(10),create_bigint_from_int(8)};
  ecdsa_point_t q={create_bigint_from_int(0),create_bigint_from_int(6)};
  bool valid=ecdsa_signature_verify(params,sig,z,q);
  TEST_ASSERT_TRUE(valid);
}

static void test_scalar_mul_identity(void)
{
  bigint_t p=BIGINT(1,17);
  bigint_t a=BIGINT(1,2);
  bigint_t b=BIGINT(1,2);
  ecdsa_params_t params={
    .p=&p,
    .a=&a,
    .b=&b
  };
  ecdsa_point_t p1 = {create_bigint_from_int(5), create_bigint_from_int(1)};
  ecdsa_point_t res = ecdsa_point_times(params, create_bigint_from_int(0), p1);
  TEST_ASSERT_TRUE(res.is_infinity);
}

static void test_addition_infinity(void)
{
  bigint_t p=BIGINT(1,17);
  bigint_t a=BIGINT(1,2);
  bigint_t b=BIGINT(1,2);
  ecdsa_params_t params={
    .p=&p,
    .a=&a,
    .b=&b
  };
  ecdsa_point_t p1 = {create_bigint_from_int(5), create_bigint_from_int(1)};
  ecdsa_point_t p3  = ecdsa_point_times(params, create_bigint_from_int(3), p1);
  ecdsa_point_t p16 = ecdsa_point_times(params, create_bigint_from_int(16), p1);
  ecdsa_point_t res = ecdsa_point_add(params, p16, p3);
  TEST_ASSERT_TRUE(res.is_infinity);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_add_point);
  RUN_TEST(test_times_point);
  RUN_TEST(test_signature_verify);
  RUN_TEST(test_times_and_add_consistency);
  RUN_TEST(test_scalar_mul_identity);
  RUN_TEST(test_addition_infinity);
  return UNITY_END();
}
