#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "x509.h"
#include "der.h"
#include "oid.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))
#define CASE(result,...) {(uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}), result}

typedef struct {
  uint8_t *data;
  size_t len;
  bool result;
} test_case;

void setUp(void)
{
}

void tearDown(void)
{
}

static void test_decode_integer()
{
  field_t parent = {0};
  parent.name = "TestSeq";
  parent.value_type = SEQUENCE;
  parent.pc = CONSTRUCTED;
  parent.required = true;

  field_t id = {0};
  id.name = "id";
  id.value_type = INTEGER;
  id.required = true;

  add_field(&parent,&id);

  uint8_t buf[] = {0x30,0x03,0x02,0x01,0x01};
  int len = ARRAY_LEN(buf);
  tlv_t actual = parse_tlv(buf,len);
  tlv_node_t *root = build_tlv(actual);
  field_value_t *out=NULL;
  bool is_valid = validate_schema(&parent, root,&out);
  TEST_ASSERT_TRUE(is_valid);
  decode(out);
  print_debug(is_valid,buf,len,root,&parent,out);
  bigint_t *bi=out->children[0]->value.bigint;
  char *result =bigint_to_decimal_str(bi);
  TEST_ASSERT_EQUAL_STRING("1",result);
}

static void test_decode_oid()
{
  field_t parent = {0};
  parent.name = "TestSeq";
  parent.value_type = SEQUENCE;
  parent.pc = CONSTRUCTED;
  parent.required = true;

  field_t id = {0};
  id.name = "oid";
  id.value_type = OBJECT_IDENTIFIER;
  id.pc = PRIMITIVE;
  id.required = true;

  add_field(&parent,&id);

  uint8_t buf[] = {0x30,0x0B,0x06,0x09,0x2A,0x82,0x48,0x87,0xBA,0x4D,0x01,0x01,0x01};
  int len = ARRAY_LEN(buf);
  tlv_t actual = parse_tlv(buf,len);
  tlv_node_t *root = build_tlv(actual);
  field_value_t *out=NULL;
  bool is_valid = validate_schema(&parent, root,&out);
  print_debug(is_valid,buf,len,root,&parent,out);
  TEST_ASSERT_TRUE(is_valid);
  decode(out);
  oid_t *oid=out->children[0]->value.oid;
  char *result =oid_to_str(oid);
  TEST_ASSERT_EQUAL_STRING("1.2.328.122189.1.1.1",result);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_decode_integer);
  RUN_TEST(test_decode_oid);
  return UNITY_END();
}
