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

static void test_double_point(void)
{
	ecdsa_params_t params={
		.p=17,
		.a=2,
		.b=2
	};
	ecdsa_point_t p1={5,1};
	ecdsa_point_t res=ecdsa_point_times(params,1,p1);
	TEST_ASSERT_EQUAL_INT(6,res.x);
	TEST_ASSERT_EQUAL_INT(3,res.y);
	ecdsa_point_t res1=ecdsa_point_times(params,2,p1);
	TEST_ASSERT_EQUAL_INT(10,res1.x);
	TEST_ASSERT_EQUAL_INT(6,res1.y);
	ecdsa_point_t res2=ecdsa_point_times(params,3,p1);
	TEST_ASSERT_EQUAL_INT(3,res2.x);
	TEST_ASSERT_EQUAL_INT(1,res2.y);
	ecdsa_point_t res3=ecdsa_point_times(params,4,p1);
	TEST_ASSERT_EQUAL_INT(9,res3.x);
	TEST_ASSERT_EQUAL_INT(16,res3.y);
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

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_double_point);
  RUN_TEST(test_add_point);
  RUN_TEST(test_mod);
  RUN_TEST(test_mod_inverse);
  RUN_TEST(test_verify);
  return UNITY_END();
}
