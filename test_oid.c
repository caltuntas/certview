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
	TEST_ASSERT_EQUAL_INT64(1,oid->arcs[0]);
	TEST_ASSERT_EQUAL_INT64(2,oid->arcs[1]);
	TEST_ASSERT_EQUAL_INT64(328,oid->arcs[2]);
	TEST_ASSERT_EQUAL_INT64(122189,oid->arcs[3]);
	TEST_ASSERT_EQUAL_INT64(1,oid->arcs[4]);
	TEST_ASSERT_EQUAL_INT64(1,oid->arcs[5]);
	TEST_ASSERT_EQUAL_INT64(1,oid->arcs[6]);
	TEST_ASSERT_EQUAL_INT64(7,oid->arc_count);
}


static void test_oid_to_str(void)
{
	uint8_t buf[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05};
	size_t len=ARRAY_LEN(buf);
	oid_t *oid =oid_create(buf,len);
  char *str =oid_to_str(oid);
  TEST_ASSERT_EQUAL_STRING("1.2.840.113549.1.1.5",str);
}


static void test_oid_registry_resolve(void)
{
  //https://oidref.com/1.2.840.113549.1.1.5
	uint8_t buf[]={0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05};
	size_t len=ARRAY_LEN(buf);
	oid_t *oid =oid_create(buf,len);
  char *expected = "1(iso).2(member-body).840(iso-us).113549(rsadsi).1(pkcs).1(pkcs1).5(sha1WithRSAEncryption)";
  char *actual=oid_to_reg_str(oid);
  TEST_ASSERT_EQUAL_STRING(expected,actual);
}

static void test_oid_registry_resolve_partial(void)
{
  //1.2.840.113549.2.1.5
  uint8_t buf[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x01,0x05};
  size_t len = ARRAY_LEN(buf);
  oid_t *oid = oid_create(buf, len);
  char *expected = "1(iso).2(member-body).840(iso-us).113549(rsadsi).2.1.5";
  char *oid_reg_str = oid_to_reg_str(oid);
  TEST_ASSERT_EQUAL_STRING(expected, oid_reg_str);
}

static void test_oid_registry_resolve_leaf(void)
{
  //1.3.14.3.2.24 md2WithRSASignature
  uint8_t buf[] = {0x2B,0x0E,0x03,0x02,0x18};
  size_t len = ARRAY_LEN(buf);
  oid_t *oid = oid_create(buf, len);
  char *expected = "1(iso).3.14.3.2.24(md2WithRSASignature)";
  char *oid_reg_str = oid_to_reg_str(oid);
  TEST_ASSERT_EQUAL_STRING(expected, oid_reg_str);
}

int main(void)
{
  UNITY_BEGIN();
	RUN_TEST(test_oid_create);
	RUN_TEST(test_oid_to_str);
	RUN_TEST(test_oid_registry_resolve);
	RUN_TEST(test_oid_registry_resolve_partial);
	RUN_TEST(test_oid_registry_resolve_leaf);
  return UNITY_END();
}
