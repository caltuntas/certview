#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "x509.h"
#include "der.h"
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

/*
AlgorithmIdentifier ::= SEQUENCE {
    algorithm   OBJECT IDENTIFIER,
    parameters  ANY DEFINED BY algorithm OPTIONAL
}
 */
static void test_add_field(void)
{
  field_t parent_field={0};	
	parent_field.name="AlgorithmIdentifier";
	parent_field.value_type=SEQUENCE;
	parent_field.required=true;

  field_t field1={0};	
	field1.name="algorithm";
	field1.value_type=OBJECT_IDENTIFIER;
	field1.required=true;
	field1.match_type=POSITION;

  field_t field2={0};	
	field2.name="parameters";
	field2.value_type=ANY;
	field2.required=false;
	field1.match_type=POSITION;

	add_field(&parent_field,&field1);
	add_field(&parent_field,&field2);

  TEST_ASSERT_EQUAL_INT(2,parent_field.count);
}

static void test_oid_only(void)
{
  field_t parent_field={0};	
	parent_field.name="AlgorithmIdentifier";
	parent_field.value_type=SEQUENCE;
  parent_field.tag_class=UNIVERSAL;
	parent_field.required=true;

  field_t field1={0};	
	field1.name="algorithm";
	field1.value_type=OBJECT_IDENTIFIER;
  field1.tag_class=UNIVERSAL;
	field1.required=true;
	field1.match_type=POSITION;

  field_t field2={0};	
	field2.name="parameters";
	field2.value_type=ANY;
	field2.required=false;
	field1.match_type=POSITION;

	add_field(&parent_field,&field1);
	add_field(&parent_field,&field2);

  uint8_t buf[]={0x30,0x0A,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);

  bool is_valid=validate_asn1(&parent_field,root);

  TEST_ASSERT_TRUE(is_valid);
}

static void test_invalid_null_first(void)
{
  field_t parent_field={0};	
	parent_field.name="AlgorithmIdentifier";
	parent_field.value_type=SEQUENCE;
	parent_field.required=true;

  field_t field1={0};	
	field1.name="algorithm";
	field1.value_type=OBJECT_IDENTIFIER;
	field1.required=true;
	field1.match_type=POSITION;

  field_t field2={0};	
	field2.name="parameters";
	field2.value_type=ANY;
	field2.required=false;
	field1.match_type=POSITION;

	add_field(&parent_field,&field1);
	add_field(&parent_field,&field2);

  uint8_t buf[]={0x30,0x0C,0x05,0x00,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);

  bool is_valid=validate_asn1(&parent_field,root);

  TEST_ASSERT_FALSE(is_valid);
}

static void test_validate(void) 
{
  field_t parent_field={0};	
	parent_field.name="AlgorithmIdentifier";
	parent_field.value_type=SEQUENCE;
  parent_field.tag_class=UNIVERSAL;
	parent_field.required=true;

  field_t field1={0};	
	field1.name="algorithm";
	field1.value_type=OBJECT_IDENTIFIER;
  field1.tag_class=UNIVERSAL;
	field1.required=true;
	field1.match_type=POSITION;

  field_t field2={0};	
	field2.name="parameters";
	field2.value_type=ANY;
	field2.required=false;
	field2.match_type=POSITION;

	add_field(&parent_field,&field1);
	add_field(&parent_field,&field2);

	test_case cases[]={
		CASE(true,0x30,0x0A,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02),
		CASE(true,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00),
		CASE(true,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07),
		CASE(false,0x30,0x0C,0x05,0x00,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02),
		CASE(false,0x30,0x0E,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02,0x05,0x00,0x05,0x00),
		CASE(false,0x30,0x03,0x02,0x01,0x01),
		CASE(true,0x30,0x0C,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02,0x30,0x00)
	};

  int len = ARRAY_LEN(cases);
  for (int i=0; i<len; i++) {
		test_case tc=cases[i];
		tlv_t actual = parse_tlv(tc.data,tc.len);
		tlv_node_t *root =build_tlv(actual);

    char msg[40];
    snprintf(msg,20,"case=%d\n",i);
		bool is_valid=validate_asn1(&parent_field,root);
		TEST_ASSERT_EQUAL_MESSAGE(tc.result,is_valid,msg);
  }
}

/*
TBSCertificate ::= SEQUENCE {
    version         [0] EXPLICIT INTEGER DEFAULT v1,
    serialNumber        INTEGER,
    ....
    ....
*/
static void test_validate_explicit(void) 
{
  field_t parent_field={0};	
	parent_field.name="TBSCertificate";
	parent_field.tag_class=UNIVERSAL;
	parent_field.value_type=SEQUENCE;
	parent_field.required=true;

  field_t field1={0};	
	field1.name="version";
	field1.tag_number=0;
  field1.tag_class=CONTEXT_SPECIFIC;
	field1.required=false;
	field1.match_type=TAG;
  field1.encoding_type=EXPLICIT;
  field1.value_type=INTEGER;
  field1.has_default=true;

  field_t field2={0};	
	field2.name="serialNumber";
	field2.tag_class=UNIVERSAL;
	field2.value_type=INTEGER;
	field2.required=true;
	field2.match_type=POSITION;

	add_field(&parent_field,&field1);
	add_field(&parent_field,&field2);

	test_case cases[]={
		CASE(true,0x30,0x03,0x02,0x01,0x01),
    CASE(true,0x30,0x08,0xA0,0x03,0x02,0x01,0x02,0x02,0x01,0x05),
    CASE(true,0x30,0x08,0xA0,0x03,0x02,0x01,0x00,0x02,0x01,0x01),
    CASE(true,0x30,0x09,0xA0,0x03,0x02,0x01,0x02,0x02,0x02,0x01,0x00),
    CASE(false,0x30,0x06,0x80,0x01,0x02,0x02,0x01,0x01),
    CASE(false,0x30,0x08,0x60,0x03,0x02,0x01,0x02,0x02,0x01,0x01),
    CASE(false,0x30,0x08,0xA0,0x03,0x05,0x01,0xFF,0x02,0x01,0x01),
    CASE(false,0x30,0x05,0xA0,0x03,0x02,0x01,0x02),
    CASE(false,0x30,0x08,0x02,0x01,0x01,0xA0,0x03,0x02,0x01,0x02),
    CASE(false,0x30,0x0D,0xA0,0x03,0x02,0x01,0x02,0xA0,0x03,0x02,0x01,0x02,0x02,0x01,0x01),
	};

  int len = ARRAY_LEN(cases);
  for (int i=0; i<len; i++) {
		test_case tc=cases[i];
		tlv_t actual = parse_tlv(tc.data,tc.len);
		tlv_node_t *root =build_tlv(actual);
    char msg[40]={0};
    snprintf(msg,20,"case=%d\n",i);
		bool is_valid=validate_asn1(&parent_field,root);
		TEST_ASSERT_EQUAL_MESSAGE(tc.result,is_valid,msg);
  }
}

/*
TBSCertificate  ::=  SEQUENCE  {
     serialNumber         CertificateSerialNumber,
     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
 */
static void test_validate_implicit(void) 
{
  field_t parent_field={0};	
	parent_field.name="TBSCertificate";
	parent_field.tag_class=UNIVERSAL;
	parent_field.value_type=SEQUENCE;
	parent_field.required=true;

  field_t field1={0};	
	field1.name="serialNumber";
  field1.tag_class=UNIVERSAL;
  field1.value_type=INTEGER;
	field1.required=true;
	field1.match_type=POSITION;

  field_t field2={0};	
	field2.name="issuerUniqueID";
	field2.tag_class=CONTEXT_SPECIFIC;
	field2.tag_number=1;
	field2.required=false;
	field2.match_type=TAG;
	field2.encoding_type=IMPLICIT;
	field2.value_type=BIT_STRING;

  field_t field3={0};	
	field3.name="subjectUniqueID";
	field3.tag_class=CONTEXT_SPECIFIC;
	field3.tag_number=2;
	field3.required=false;
	field3.match_type=TAG;
	field3.encoding_type=IMPLICIT;
	field3.value_type=BIT_STRING;

	add_field(&parent_field,&field1);
	add_field(&parent_field,&field2);
	add_field(&parent_field,&field3);

	test_case cases[]={
    CASE(true,0x30,0x0B,0x02,0x01,0x64,0x81,0x02,0x04,0xC0,0x82,0x02,0x04,0xA0),
    CASE(true,0x30,0x06,0x02,0x01,0x64,0x81,0x02,0x04,0xC0),
    CASE(false,0x30,0x08,0x02,0x01,0x64,0x81,0x02,0x04,0xC0),
    CASE(false,0x30,0x0D,0x02,0x01,0x64,0xA1,0x04,0x03,0x02,0x04,0xC0,0xA2,0x04,0x03,0x02,0x04,0xA0),
    CASE(false,0x30,0x08,0x02,0x01,0x64,0x83,0x02,0x04,0xC0,0x82,0x02,0x04,0xA0),
    CASE(false, 0x30,0x0B, 0x02,0x01,0x64, 0x82,0x02,0x04,0xA0, 0x81,0x02,0x04,0xC0 ),
    CASE(false, 0x30,0x0E, 0x02,0x01,0x64, 0x81,0x02,0x04,0xC0, 0x81,0x02,0x04,0xC0),
    CASE(false, 0x30,0x0B, 0x02,0x01,0x64, 0xA1,0x02,0x04,0xC0),
    CASE(false, 0x30,0x0B, 0x02,0x01,0x64, 0x81,0x02,0x08,0xFF),
    CASE(false, 0x30,0x0B, 0x02,0x01,0x64, 0x81,0x01,0xFF),
    CASE(false, 0x30,0x0E, 0x02,0x01,0x64, 0x81,0x02,0x04,0xC0, 0x83,0x02,0x04,0xA0)
  };

  int len = ARRAY_LEN(cases);
  for (int i=0; i<len; i++) {
		test_case tc=cases[i];
		tlv_t actual = parse_tlv(tc.data,tc.len);
		tlv_node_t *root =build_tlv(actual);
    char msg[40]={0};
    snprintf(msg,20,"case=%d\n",i);
		bool is_valid=validate_asn1(&parent_field,root);
		TEST_ASSERT_EQUAL_MESSAGE(tc.result,is_valid,msg);
  }
}

/*
Example ::= SEQUENCE {
    foo   INTEGER,
    bar   CHOICE {
        a UTF8String,
        b OBJECT IDENTIFIER,
        c SEQUENCE OF INTEGER
    }
}
 */
static void test_validate_choice()
{
  field_t parent_field={0};	
	parent_field.name="Example";
	parent_field.tag_class=UNIVERSAL;
	parent_field.value_type=SEQUENCE;
	parent_field.required=true;

  field_t field1={0};	
	field1.name="foo";
  field1.tag_class=UNIVERSAL;
  field1.value_type=INTEGER;
	field1.required=true;
	field1.match_type=POSITION;

  field_t field2 = {0};
  field2.name = "bar";
  field2.value_type = CHOICE;
  field2.match_type = POSITION;
  field2.required = true;

  field_t option1={0};	
	option1.name="a";
	option1.tag_class=UNIVERSAL;
	option1.value_type=UTF8String;

  field_t option2={0};	
	option2.name="b";
	option2.tag_class=UNIVERSAL;
	option2.value_type=OBJECT_IDENTIFIER;

  field_t option3={0};	
	option3.name="c";
	option3.tag_class=UNIVERSAL;
	option3.value_type=SEQUENCE;
  option3.element_type=INTEGER;

	add_field(&parent_field,&field1);
	add_field(&parent_field,&field2);

	add_field(&field2,&option1);
	add_field(&field2,&option2);
	add_field(&field2,&option3);

	test_case cases[]={
    CASE(true,0x30,0x08,0x02,0x01,0x01,0x0C,0x03,0x66,0x6F,0x6F),
    CASE(true,0x30,0x0A,0x02,0x01,0x01,0x06,0x05,0x2A,0x86,0x48,0x86,0xF7),
    CASE(true,0x30,0x0A,0x02,0x01,0x01,0x30,0x05,0x02,0x01,0x01),
    CASE(false,0x30,0x03,0x02,0x01,0x01),
    CASE(false,0x30,0x07,0x02,0x01,0x01,0x01,0x01,0x01,0x01),
    CASE(false,0x30,0x10,0x02,0x01,0x01,0x06,0x06,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x0C,0x03,0x66,0x6F,0x6F),
  };

  int len = ARRAY_LEN(cases);
  for (int i=0; i<len; i++) {
		test_case tc=cases[i];
		tlv_t actual = parse_tlv(tc.data,tc.len);
		tlv_node_t *root =build_tlv(actual);
    char msg[40]={0};
    snprintf(msg,20,"case=%d\n",i);
		bool is_valid=validate_asn1(&parent_field,root);
		TEST_ASSERT_EQUAL_MESSAGE(tc.result,is_valid,msg);
  }

}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_add_field);
  RUN_TEST(test_oid_only);
  RUN_TEST(test_invalid_null_first);
  RUN_TEST(test_validate);
  RUN_TEST(test_validate_explicit);
  RUN_TEST(test_validate_implicit);
  RUN_TEST(test_validate_choice);
  return UNITY_END();
}
