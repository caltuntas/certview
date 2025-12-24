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

static void test_parse_tlv_long_len_1(void)
{
  uint8_t buf[244]={0x04,0x81,0xF4};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  TEST_ASSERT_EQUAL_INT(actual.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(actual.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(actual.tag.number,OCTET_STRING);
  TEST_ASSERT_EQUAL_INT(244,actual.len);
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

static void test_parse_tlv_boolean(void)
{
  uint8_t buf[]={0x01,0x01,0xFF};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  TEST_ASSERT_EQUAL_INT(actual.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(actual.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(actual.tag.number,BOOLEAN);
  TEST_ASSERT_EQUAL_INT(actual.len,1);
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

static void test_build_tlv_nested_multiple_null_types(void)
{
  uint8_t buf[]={0x30,0x0E,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02,0x05,0x00,0x05,0x00};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,14);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+2));
  TEST_ASSERT_EQUAL_INT(root->count,3);

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,OBJECT_IDENTIFIER);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,8);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+4));

  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.number,NULL_VALUE);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.len,0);
  TEST_ASSERT_EQUAL_PTR(root->children[1].tlv.value,NULL);

  TEST_ASSERT_EQUAL_INT(root->children[2].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[2].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[2].tlv.tag.number,NULL_VALUE);
  TEST_ASSERT_EQUAL_INT(root->children[2].tlv.len,0);
  TEST_ASSERT_EQUAL_PTR(root->children[2].tlv.value,NULL);
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

static void test_build_tlv_explicit_nested(void)
{
  uint8_t buf[]={ 0xA3,0x05,0x30,0x03,0x02,0x01,0x05 };
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,CONTEXT_SPECIFIC);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,3);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,5);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+2));
  TEST_ASSERT_EQUAL_INT(root->count,1);

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,3);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+4));
  TEST_ASSERT_EQUAL_INT(root->children[0].count,1);

  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.tag.number,INTEGER);
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].tlv.len,1);
  TEST_ASSERT_EQUAL_PTR(root->children[0].children[0].tlv.value,(buf+6));
  TEST_ASSERT_EQUAL_INT(root->children[0].children[0].count,0);
}

static void test_build_tlv_octet_string(void)
{
  uint8_t buf[]={0x30,0x82,0x01,0x03,0x06,0x0A,0x2B,0x06,0x01,0x04,0x01,0xD6,0x79,0x02,0x04,0x02,0x04,0x81,0xF4,0x04,0x81,0xF1,0x00,0xEF,0x00,0x76,0x00,0x64,0x11,0xC4,0x6C,0xA4,0x12,0xEC,0xA7,0x89,0x1C,0xA2,0x02,0x2E,0x00,0xBC,0xAB,0x4F,0x28,0x07,0xD4,0x1E,0x35,0x27,0xAB,0xEA,0xFE,0xD5,0x03,0xC9,0x7D,0xCD,0xF0,0x00,0x00,0x01,0x9B,0x28,0xB5,0xFA,0x2B,0x00,0x00,0x04,0x03,0x00,0x47,0x30,0x45,0x02,0x20,0x7E,0xAD,0x92,0x14,0xE5,0xE3,0xA9,0x4F,0xD2,0xFF,0xFC,0x3A,0xAC,0xE6,0x57,0x45,0x6F,0xE8,0x35,0x76,0x07,0x01,0x8C,0xE2,0xD8,0xB7,0x5E,0x80,0xD1,0x43,0x59,0xC5,0x02,0x21,0x00,0xF3,0xA4,0x73,0x6B,0xB2,0x59,0x74,0x9E,0xB4,0xEB,0xF2,0x22,0x71,0xE5,0xF2,0x9F,0x15,0x68,0x8F,0x21,0x93,0xF6,0x59,0xFC,0x0A,0xE7,0xA3,0xC2,0xA9,0xC4,0xBF,0x41,0x00,0x75,0x00,0xCB,0x38,0xF7,0x15,0x89,0x7C,0x84,0xA1,0x44,0x5F,0x5B,0xC1,0xDD,0xFB,0xC9,0x6E,0xF2,0x9A,0x59,0xCD,0x47,0x0A,0x69,0x05,0x85,0xB0,0xCB,0x14,0xC3,0x14,0x58,0xE7,0x00,0x00,0x01,0x9B,0x28,0xB5,0xFA,0x4C,0x00,0x00,0x04,0x03,0x00,0x46,0x30,0x44,0x02,0x20,0x7C,0xB5,0x77,0x32,0x6A,0xA9,0xCE,0xE3,0x12,0xD5,0xB0,0x3D,0xE9,0x93,0x01,0x81,0xA9,0x89,0x58,0xF7,0x7C,0xB9,0x11,0x85,0x0D,0xF2,0x69,0xCD,0x39,0xD1,0xA0,0x98,0x02,0x20,0x1A,0x31,0xF3,0xB9,0xB9,0xAA,0x2A,0x30,0x10,0x32,0x0E,0x38,0xE6,0x19,0xB3,0xEE,0x5D,0x1F,0x99,0x8F,0xED,0x2C,0xAE,0xC0,0x5C,0xB9,0xEB,0xFE,0xE5,0xC1,0xC3,0x6A};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,SEQUENCE);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,259);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+4));
  TEST_ASSERT_EQUAL_INT(root->count,2);

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,OBJECT_IDENTIFIER);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,10);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+6));
  TEST_ASSERT_EQUAL_INT(root->children[0].count,0);

  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.tag.number,OCTET_STRING);
  TEST_ASSERT_EQUAL_INT(root->children[1].tlv.len,244);
  TEST_ASSERT_EQUAL_PTR(root->children[1].tlv.value,(buf+19));
  TEST_ASSERT_EQUAL_INT(root->children[1].count,0);
}

static void test_build_tlv_constructed(void)
{
  uint8_t buf[]={0xA0,0x03,0x02,0x01,0x02};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);

  TEST_ASSERT_EQUAL_INT(root->tlv.tag.class,CONTEXT_SPECIFIC);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.type,CONSTRUCTED);
  TEST_ASSERT_EQUAL_INT(root->tlv.tag.number,0);
  TEST_ASSERT_EQUAL_INT(root->tlv.len,3);
  TEST_ASSERT_EQUAL_INT(root->count,1);
  TEST_ASSERT_EQUAL_PTR(root->tlv.value,(buf+2));

  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.class,UNIVERSAL);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.type,PRIMITIVE);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.tag.number,INTEGER);
  TEST_ASSERT_EQUAL_INT(root->children[0].tlv.len,1);
  TEST_ASSERT_EQUAL_INT(root->children[0].count,0);
  TEST_ASSERT_EQUAL_PTR(root->children[0].tlv.value,(buf+4));
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
  RUN_TEST(test_build_tlv_explicit_nested);
  RUN_TEST(test_parse_tlv_boolean);
  RUN_TEST(test_build_tlv_octet_string);
  RUN_TEST(test_parse_tlv_long_len_1);
  RUN_TEST(test_build_tlv_nested_multiple_null_types);
  RUN_TEST(test_build_tlv_constructed);
  return UNITY_END();
}
