#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "der.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))

void setUp(void)
{
}

void tearDown(void)
{
}

static void test_parse_tlv_short_len(void)
{
  uint8_t buf[3]={0x02,0x01,0x05};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  TEST_ASSERT_EQUAL_INT(actual.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(actual.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(actual.tag.number,INTEGER);
  TEST_ASSERT_EQUAL_INT(actual.len,1);
  TEST_ASSERT_EQUAL_PTR(actual.value,(buf+2));
}

static void test_parse_tlv_long_len(void)
{
  uint8_t buf[265]={0x02,0x82,0x01,0x05};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  TEST_ASSERT_EQUAL_INT(actual.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(actual.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(actual.tag.number,INTEGER);
  TEST_ASSERT_EQUAL_INT(actual.len,261);
  TEST_ASSERT_EQUAL_PTR(actual.value,(buf+4));
}

static void test_parse_tlv_squence(void)
{
  uint8_t buf[]={0x30,0x03,0x02,0x01,0x05};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  TEST_ASSERT_EQUAL_INT(actual.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(actual.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(actual.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(actual.len,3);
  TEST_ASSERT_EQUAL_PTR(actual.value,(buf+2));
}

static void test_parse_tlv_constructed(void)
{
  uint8_t buf[]={0xA0,0x03,0x02,0x01,0x02};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  TEST_ASSERT_EQUAL_INT(actual.tag.class,CONTEXT_SPECIFIC);
  TEST_ASSERT_EQUAL_INT(actual.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(actual.tag.number,0);
  TEST_ASSERT_EQUAL_INT(actual.len,3);
  TEST_ASSERT_EQUAL_PTR(actual.value,(buf+2));
}

static void test_build_tlv_tree(void)
{
  uint8_t buf[]={0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x02};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,6);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+2));
  TEST_ASSERT_EQUAL_INT(root->count,2);

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,INTEGER);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,1);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+4));

  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.number,INTEGER);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.len,1);
  TEST_ASSERT_EQUAL_PTR(root->children[1].tlv.value,(buf+7));
}

static void test_build_tlv_nested_sequence(void)
{
  uint8_t buf[]={0x30,0x05,0x30,0x03,0x02,0x01,0x05};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,5);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+2));
  TEST_ASSERT_EQUAL_INT(root->count,1);

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,3);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+4));

  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.number,INTEGER);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.len,1);
  TEST_ASSERT_EQUAL_PTR(root->children[0].children[0].tlv.value,(buf+6));
}

static void test_build_tlv_nested_context_specific(void)
{
  uint8_t buf[]={0x30,0x08,0xA0,0x03,0x02,0x01,0x02,0x02,0x01,0x05};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,8);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+2));
  TEST_ASSERT_EQUAL_INT(root->count,2);

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,CONTEXT_SPECIFIC);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,0);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,3);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+4));

  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.number,INTEGER);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.len,1);
  TEST_ASSERT_EQUAL_PTR(root->children[0].children[0].tlv.value,(buf+6));

  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.number,INTEGER);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.len,1);
  TEST_ASSERT_EQUAL_PTR(root->children[1].tlv.value,(buf+9));
}

static void test_build_tlv_nested_oid(void)
{
  uint8_t buf[]={0x30,0x04,0x06,0x02,0x2A,0x03};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,4);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+2));
  TEST_ASSERT_EQUAL_INT(root->count,1);

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,OBJECT_IDENTIFIER);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,2);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+4));
}

static void test_build_tlv_nested_oid_multi_byte(void)
{
  uint8_t buf[]={0x30,0x05,0x06,0x03,0x2A,0x86,0x48 };
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,5);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+2));
  TEST_ASSERT_EQUAL_INT(root->count,1);

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,OBJECT_IDENTIFIER);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,3);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+4));
}

static void test_build_tlv_nested_null_type(void)
{
  uint8_t buf[]={0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B,0x05,0x00 };
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,13);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+2));
  TEST_ASSERT_EQUAL_INT(root->count,2);

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,OBJECT_IDENTIFIER);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,9);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+4));

  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.number,NULL_VALUE);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.len,0);
  TEST_ASSERT_EQUAL_PTR(root->children[1].tlv.value,NULL);
}

static void test_build_tlv_optional(void)
{
  uint8_t buf[]={0x30,0x05,0xA0,0x03,0x02,0x01,0x02 };
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,5);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+2));
  TEST_ASSERT_EQUAL_INT(root->count,1);

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,CONTEXT_SPECIFIC);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,0);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,3);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+4));

  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.number,INTEGER);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.len,1);
  TEST_ASSERT_EQUAL_PTR(root->children[0].children[0].tlv.value,(buf+6));
}

static void test_build_tlv_explicit(void)
{
  uint8_t buf[]={0xA3,0x0D,0x30,0x0B,0x30,0x09,0x06,0x03,0x55,0x1D,0x13,0x04,0x02,0x30,0x00 };
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,CONTEXT_SPECIFIC);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,3);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,13);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+2));
  TEST_ASSERT_EQUAL_INT(root->count,1);

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,11);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+4));
  TEST_ASSERT_EQUAL_INT(root->children[0].count,1);

  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.len,9);
  TEST_ASSERT_EQUAL_PTR(root->children[0].children[0].tlv.value,(buf+6));
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].count,2);

  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].children[0].tlv.tag.number,OBJECT_IDENTIFIER);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].children[0].tlv.len,3);
  TEST_ASSERT_EQUAL_PTR(root->children[0].children[0].children[0].tlv.value,(buf+8));

  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].children[1].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].children[1].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].children[1].tlv.tag.number,OCTET_STRING);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].children[1].tlv.len,2);
  TEST_ASSERT_EQUAL_PTR(root->children[0].children[0].children[1].tlv.value,(buf+13));
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_parse_tlv_short_len);
  RUN_TEST(test_parse_tlv_long_len);
  RUN_TEST(test_parse_tlv_squence);
  RUN_TEST(test_parse_tlv_constructed);
  RUN_TEST(test_build_tlv_tree);
  RUN_TEST(test_build_tlv_nested_sequence);
  RUN_TEST(test_build_tlv_nested_context_specific);
  RUN_TEST(test_build_tlv_nested_oid);
  RUN_TEST(test_build_tlv_nested_oid_multi_byte);
  RUN_TEST(test_build_tlv_nested_null_type);
  RUN_TEST(test_build_tlv_optional);
  RUN_TEST(test_build_tlv_explicit);
  return UNITY_END();
}
