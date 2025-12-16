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

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_parse_tlv_short_len);
  RUN_TEST(test_parse_tlv_long_len);
  RUN_TEST(test_parse_tlv_squence);
  RUN_TEST(test_parse_tlv_constructed);
  RUN_TEST(test_build_tlv_tree);
  return UNITY_END();
}
