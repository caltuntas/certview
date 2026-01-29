#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "oid.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))

void setUp(void)
{
}

void tearDown(void)
{
}


static void test_oid_create(void)
{
	uint8_t buf[]={0x2A,0x82,0x48,0x87,0xBA,0x4D,0x01,0x01,0x01};
	size_t len=ARRAY_LEN(buf);
	oid_t *oid =oid_create(buf,len);

	TEST_ASSERT_EQUAL_INT(1,oid->arcs[0]);
	TEST_ASSERT_EQUAL_INT(2,oid->arcs[1]);
	TEST_ASSERT_EQUAL_INT(328,oid->arcs[2]);
	TEST_ASSERT_EQUAL_INT(122189,oid->arcs[3]);
	TEST_ASSERT_EQUAL_INT(1,oid->arcs[4]);
	TEST_ASSERT_EQUAL_INT(1,oid->arcs[5]);
	TEST_ASSERT_EQUAL_INT(1,oid->arcs[6]);
	TEST_ASSERT_EQUAL_INT(7,oid->arc_count);
}


int main(void)
{
  UNITY_BEGIN();
	RUN_TEST(test_oid_create);
  return UNITY_END();
}
