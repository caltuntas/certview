#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "asn1.h"
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
  decode(out,NULL);
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
  decode(out,NULL);
  oid_t *oid=out->children[0]->value.oid;
  char *result =oid_to_str(oid);
  TEST_ASSERT_EQUAL_STRING("1.2.328.122189.1.1.1",result);
}

static void test_decode_bit_string()
{
  field_t parent = {0};
  parent.name = "TestSeq";
  parent.value_type = SEQUENCE;
  parent.pc = CONSTRUCTED;
  parent.required = true;

  field_t id = {0};
  id.name = "bitstring";
  id.value_type = BIT_STRING;
  id.pc = PRIMITIVE;
  id.required = true;

  add_field(&parent,&id);

  uint8_t buf[] = {0x30,0x05,0x03,0x03,0x03,0x6F,0xE0};
  int len = ARRAY_LEN(buf);
  tlv_t actual = parse_tlv(buf,len);
  tlv_node_t *root = build_tlv(actual);
  field_value_t *out=NULL;
  bool is_valid = validate_schema(&parent, root,&out);
  print_debug(is_valid,buf,len,root,&parent,out);
  TEST_ASSERT_TRUE(is_valid);
  decode(out,NULL);
  bit_string_t *bitstr=out->children[0]->value.bitstring;
  TEST_ASSERT_EQUAL_INT(3,bitstr->unused_bits);
  TEST_ASSERT_EQUAL_INT(3,bitstr->length);
  TEST_ASSERT_EQUAL_INT(13,bitstr->bit_length);
  char *bits=bit_string_to_str(bitstr);
  TEST_ASSERT_EQUAL_STRING("0110111111100",bits);
}

static void test_decode_octet_string()
{
  field_t parent = {0};
  parent.name = "TestSeq";
  parent.value_type = SEQUENCE;
  parent.pc = CONSTRUCTED;
  parent.required = true;

  field_t id = {0};
  id.name = "octetstring";
  id.value_type = OCTET_STRING;
  id.pc = PRIMITIVE;
  id.required = true;

  add_field(&parent,&id);

  uint8_t buf[] = {0x30,0x0B,0x04,0x09,0x68,0x65,0x6C,0x6C,0x6F,0x2E,0x63,0x6F,0x6D};
  int len = ARRAY_LEN(buf);
  tlv_t actual = parse_tlv(buf,len);
  tlv_node_t *root = build_tlv(actual);
  field_value_t *out=NULL;
  bool is_valid = validate_schema(&parent, root,&out);
  print_debug(is_valid,buf,len,root,&parent,out);
  TEST_ASSERT_TRUE(is_valid);
  decode(out,NULL);
  octet_string_t *os=out->children[0]->value.octetstring;
  TEST_ASSERT_EQUAL_INT(9,os->length);
  char *str=octet_string_to_str(os);
  TEST_ASSERT_EQUAL_STRING("hello.com",str);
}

static void test_decode_custom_octet_string()
{
  field_t extension ={0};
  extension.name = "Extension";
  extension.value_type = SEQUENCE;
  extension.pc = CONSTRUCTED;
  extension.required = true;

  field_t extnID ={0};
  extnID.name = "extnID";
  extnID.value_type = OBJECT_IDENTIFIER;
  extnID.required = true;

  field_t critical ={0};
  critical.name = "critical";
  critical.value_type = BOOLEAN;
  critical.required = false;
  critical.has_default = true;

  field_t extnValue ={0};
  extnValue.name = "extnValue";
  extnValue.value_type = OCTET_STRING;
  extnValue.required = true;

  add_field(&extension, &extnID);
  add_field(&extension, &critical);
  add_field(&extension, &extnValue);

  uint8_t buf[] = {0x30,0x0C,0x06,0x03,0x55,0x1D,0x13,0x01,0x01,0xFF,0x04,0x02,0x30,0x00};
  int len = ARRAY_LEN(buf);
  tlv_t actual = parse_tlv(buf,len);
  tlv_node_t *root = build_tlv(actual);
  field_value_t *out=NULL;
  bool is_valid = validate_schema(&extension, root,&out);
  TEST_ASSERT_TRUE(is_valid);
  decoder_t basic_const_decoder={0};
  basic_const_decoder.field_value_type=OCTET_STRING;
  basic_const_decoder.decoder_func=decode_basic_constraints;
  decode(out,&basic_const_decoder);
  print_debug(is_valid,buf,len,root,&extension,out);
  field_value_t *bc_fv=out->children[2]->children[0];
  TEST_ASSERT_EQUAL_STRING("BasicConstraints",bc_fv->field->name);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_decode_integer);
  RUN_TEST(test_decode_oid);
  RUN_TEST(test_decode_bit_string);
  RUN_TEST(test_decode_octet_string);
  RUN_TEST(test_decode_custom_octet_string);
  return UNITY_END();
}
