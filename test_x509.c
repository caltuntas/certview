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
	field2.match_type=POSITION;

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
	field2.match_type=POSITION;

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
	field2.match_type=POSITION;

	add_field(&parent_field,&field1);
	add_field(&parent_field,&field2);

  uint8_t buf[]={0x30,0x0C,0x05,0x00,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
  tlv_t actual = parse_tlv(buf,ARRAY_LEN(buf));
  tlv_node_t *root =build_tlv(actual);

  bool is_valid=validate_asn1(&parent_field,root);

  TEST_ASSERT_FALSE(is_valid);
}

/*
AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm               OBJECT IDENTIFIER,
     parameters              ANY DEFINED BY algorithm OPTIONAL
 */
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
		CASE(true,0x30,0x03,0x02,0x01,0x01),//0
    CASE(true,0x30,0x08,0xA0,0x03,0x02,0x01,0x02,0x02,0x01,0x05),//1
    CASE(true,0x30,0x08,0xA0,0x03,0x02,0x01,0x00,0x02,0x01,0x01),//2
    CASE(true,0x30,0x09,0xA0,0x03,0x02,0x01,0x02,0x02,0x02,0x01,0x00),//3
    CASE(false,0x30,0x06,0x80,0x01,0x02,0x02,0x01,0x01),//4
    CASE(false,0x30,0x08,0x60,0x03,0x02,0x01,0x02,0x02,0x01,0x01),//5
    CASE(false,0x30,0x08,0xA0,0x03,0x05,0x01,0xFF,0x02,0x01,0x01),//6
    CASE(false,0x30,0x05,0xA0,0x03,0x02,0x01,0x02),//7
    CASE(false,0x30,0x08,0x02,0x01,0x01,0xA0,0x03,0x02,0x01,0x02),//8
    CASE(false,0x30,0x0D,0xA0,0x03,0x02,0x01,0x02,0xA0,0x03,0x02,0x01,0x02,0x02,0x01,0x01),//9
	};

  int len = ARRAY_LEN(cases);
  for (int i=0; i<len; i++) {
		test_case tc=cases[i];
		tlv_t actual = parse_tlv(tc.data,tc.len);
		tlv_node_t *root =build_tlv(actual);
    char msg[40]={0};
    snprintf(msg,20,"case=%d\n",i);
		bool is_valid=validate_asn1(&parent_field,root);
    if(is_valid!=tc.result){
      print_field(&parent_field,0);
      print_tlv_node(root,0);
    }
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
    CASE(true,0x30,0x0B,0x02,0x01,0x64,0x81,0x02,0x04,0xC0,0x82,0x02,0x04,0xA0),//0
    CASE(true,0x30,0x07,0x02,0x01,0x64,0x81,0x02,0x04,0xC0),//1
    CASE(true,0x30,0x07,0x02,0x01,0x64,0x81,0x02,0x04,0xC0),//2
    CASE(false,0x30,0x0F,0x02,0x01,0x64,0xA1,0x04,0x03,0x02,0x04,0xC0,0xA2,0x04,0x03,0x02,0x04,0xA0),//3
    CASE(false,0x30,0x0B,0x02,0x01,0x64,0x83,0x02,0x04,0xC0,0x82,0x02,0x04,0xA0),//4
    CASE(false,0x30,0x0B,0x02,0x01,0x64,0x82,0x02,0x04,0xA0,0x81,0x02,0x04,0xC0),//5
    CASE(false,0x30,0x0B,0x02,0x01,0x64,0x81,0x02,0x04,0xC0,0x81,0x02,0x04,0xC0),//6
    CASE(false,0x30,0x07,0x02,0x01,0x64,0xA1,0x02,0x04,0xC0),//7
    CASE(true,0x30,0x07,0x02,0x01,0x64,0x81,0x02,0x08,0xFF),//8
    CASE(true,0x30,0x06,0x02,0x01,0x64,0x81,0x01,0xFF),//9
    CASE(false,0x30,0x0B,0x02,0x01,0x64,0x81,0x02,0x04,0xC0,0x83,0x02,0x04,0xA0)//10
  };

  int len = ARRAY_LEN(cases);
  for (int i=0; i<len; i++) {
		test_case tc=cases[i];
		tlv_t actual = parse_tlv(tc.data,tc.len);
		tlv_node_t *root =build_tlv(actual);
    char msg[40]={0};
    snprintf(msg,20,"case=%d\n",i);
		bool is_valid=validate_asn1(&parent_field,root);
    if(is_valid!=tc.result){
      print_field(&parent_field,0);
      print_tlv_node(root,0);
    }
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
  option3.element_type=REFERENCE_TYPE;

  field_t o3i = {0};
  o3i.value_type=INTEGER;
  o3i.required=true;
  o3i.has_default=false;


	add_field(&parent_field,&field1);
	add_field(&parent_field,&field2);

	add_field(&field2,&option1);
	add_field(&field2,&option2);
	add_field(&field2,&option3);

	add_field(&option3,&o3i);

	test_case cases[]={
    CASE(true,0x30,0x08,0x02,0x01,0x01,0x0C,0x03,0x66,0x6F,0x6F),
    CASE(true,0x30,0x0A,0x02,0x01,0x01,0x06,0x05,0x2A,0x86,0x48,0x86,0xF7),
    CASE(true,0x30,0x08,0x02,0x01,0x01,0x30,0x03,0x02,0x01,0x01),
    CASE(true,0x30,0x0C,0x02,0x01,0x2A,0x30,0x07,0x02,0x01,0x00,0x02,0x02,0xFF,0x9C),
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
    if(is_valid!=tc.result){
      print_field(&parent_field,0);
      print_tlv_node(root,0);
    }
		TEST_ASSERT_EQUAL_MESSAGE(tc.result,is_valid,msg);
  }

}

/*
AlgorithmIdentifier ::= SEQUENCE {
    algorithm   OBJECT IDENTIFIER,
    parameters  ANY DEFINED BY algorithm OPTIONAL
}
SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm            AlgorithmIdentifier,
    subjectPublicKey     BIT STRING
}
 */
static void test_validate_nested_fields()
{
  field_t algo_field={0};	
	algo_field.name="AlgorithmIdentifier";
	algo_field.value_type=SEQUENCE;
	algo_field.required=true;

  field_t field1={0};	
	field1.name="algorithm";
	field1.value_type=OBJECT_IDENTIFIER;
	field1.required=true;
	field1.match_type=POSITION;

  field_t field2={0};	
	field2.name="parameters";
	field2.value_type=ANY;
	field2.required=false;
	field2.match_type=POSITION;

  field_t parent_field={0};	
	parent_field.name="SubjectPublicKeyInfo";
	parent_field.value_type=SEQUENCE;
	parent_field.required=true;

  field_t field4={0};	
	field4.name="algorithm";
	field4.value_type=REFERENCE_TYPE;
	field4.reference_type="AlgorithmIdentifier";
	field4.required=true;
	field4.match_type=POSITION;

  field_t field3={0};	
	field3.name="subjectPublicKey";
	field3.tag_class=UNIVERSAL;
	field3.required=true;
	field3.value_type=BIT_STRING;
  field3.match_type=POSITION;

  add_field(&algo_field,&field1);
  add_field(&algo_field,&field2);

  add_field(&field4,&algo_field);

  add_field(&parent_field,&field4);
  add_field(&parent_field,&field3);

	test_case cases[]={
    CASE(true,0x30,0x11,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00,0x03,0x00),
    CASE(true,0x30,0x13,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00,0x03,0x01,0x00,0x00),
    CASE(false,0x30,0x03,0x03,0x01,0x00,0x00),
    CASE(false,0x30,0x11,0x03,0x00,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00),
    CASE(false,0x30,0x0B,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x03,0x00),
    CASE(false,0x30,0x09,0x30,0x03,0x05,0x01,0x00,0x03,0x01,0x00,0x00),
  };

  int len = ARRAY_LEN(cases);
  for (int i=0; i<len; i++) {
		test_case tc=cases[i];
		tlv_t actual = parse_tlv(tc.data,tc.len);
		tlv_node_t *root =build_tlv(actual);
    char msg[40]={0};
    snprintf(msg,20,"case=%d\n",i);
		bool is_valid=validate_asn1(&parent_field,root);
    if(is_valid!=tc.result){
      print_field(&parent_field,0);
      print_tlv_node(root,0);
    }
		TEST_ASSERT_EQUAL_MESSAGE(tc.result,is_valid,msg);
  }
}

/*
Numbers ::= SEQUENCE OF INTEGER
 */
static void test_validate_sequence_of()
{
  field_t parent = {0};
  parent.name = "Numbers";
  parent.value_type = SEQUENCE;
  parent.required = true;
  parent.element_type = REFERENCE_TYPE;

  field_t field1 = {0};
  field1.value_type=INTEGER;
  field1.required=true;
  field1.has_default=false;

  add_field(&parent,&field1);

  test_case cases[] = {
    CASE(true,0x30,0x09,0x02,0x01,0x01,0x02,0x01,0x02,0x02,0x01,0x03),
    CASE(false,0x30,0x09,0x02,0x01,0x01,0x0C,0x01,'A',0x02,0x01,0x02),
    CASE(false,0x30,0x00),
    CASE(false,0x30,0x05,0x30,0x03,0x02,0x01,0x01),
  };

  int len = ARRAY_LEN(cases);
  for (int i = 0; i < len; i++) {
    test_case tc = cases[i];
    tlv_t actual = parse_tlv(tc.data, tc.len);
    tlv_node_t *root = build_tlv(actual);
    char msg[40] = {0};
    snprintf(msg, 20, "case=%d\n", i);
    bool is_valid = validate_asn1(&parent, root);
    if(is_valid!=tc.result){
      print_field(&parent,0);
      print_tlv_node(root,0);
    }
    TEST_ASSERT_EQUAL_MESSAGE(tc.result, is_valid, msg);
  }
}

/*
Name ::= SEQUENCE OF RelativeDistinguishedName
RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
AttributeTypeAndValue ::= SEQUENCE {
    type    OBJECT IDENTIFIER,
    value   ANY
}
*/
static void test_validate_set()
{
  field_t parent = {0};
  parent.name = "Name";
  parent.value_type = SEQUENCE;
  parent.required = true;
  parent.element_type = REFERENCE_TYPE;
  parent.reference_type = "RelativeDistinguishedName";
  
  field_t field1 = {0};
  field1.name="RelativeDistinguishedName";
  field1.value_type=SET;
  field1.element_type=REFERENCE_TYPE;
  field1.reference_type="AttributeTypeAndValue";

  field_t field2={0};
  field2.name="AttributeTypeAndValue";
  field2.value_type=SEQUENCE;
  field2.required=true;

  field_t field3={0};
  field3.name="type";
  field3.value_type=OBJECT_IDENTIFIER;
  field3.required=true;

  field_t field4={0};
  field4.name="value";
  field4.value_type=ANY;
  field4.required=true;

  add_field(&parent,&field1);
  add_field(&field1,&field2);
  add_field(&field2,&field3);
  add_field(&field2,&field4);

  test_case cases[] = {
    CASE(true,0x30,0x13,0x31,0x11,0x30,0x0F,0x06,0x03,0x55,0x04,0x03,0x0C,0x08,0x4A,0x6F,0x68,0x6E,0x20,0x44,0x6F,0x65),
    CASE(true,0x30,0x1E,0x31,0x1C,0x30,0x0F,0x06,0x03,0x55,0x04,0x03,0x0C,0x08,0x4A,0x6F,0x68,0x6E,0x20,0x44,0x6F,0x65,0x30,0x09,0x06,0x03,0x55,0x04,0x07,0x0C,0x02,0x43,0x41),
    CASE(true,0x30,0x0B,0x31,0x09,0x30,0x07,0x06,0x03,0x55,0x04,0x03,0x0C,0x00),
    CASE(true,0x30,0x0E,0x31,0x0C,0x30,0x0A,0x06,0x03,0x55,0x04,0x06,0x13,0x07,0x55,0x53,0x41),
    CASE(false,0x31,0x13,0x31,0x11,0x30,0x0F,0x06,0x03,0x55,0x04,0x03,0x0C,0x08,0x4A,0x6F,0x68,0x6E,0x20,0x44,0x6F,0x65),
    CASE(false,0x30,0x13,0x30,0x11,0x30,0x0F,0x06,0x03,0x55,0x04,0x03,0x0C,0x08,0x4A,0x6F,0x68,0x6E,0x20,0x44,0x6F,0x65),
    CASE(false,0x30,0x0E,0x31,0x0C,0x30,0x0A,0x0C,0x08,0x4A,0x6F,0x68,0x6E,0x20,0x44,0x6F,0x65),
  };

  int len = ARRAY_LEN(cases);
  for (int i = 0; i < len; i++) {
    test_case tc = cases[i];
    tlv_t actual = parse_tlv(tc.data, tc.len);
    tlv_node_t *root = build_tlv(actual);
    char msg[40] = {0};
    snprintf(msg, 20, "case=%d\n", i);
    bool is_valid = validate_asn1(&parent, root);
    if(is_valid!=tc.result){
      print_field(&parent,0);
      print_tlv_node(root,0);
    }
    TEST_ASSERT_EQUAL_MESSAGE(tc.result, is_valid, msg);
  }
}

/*
Example ::= SEQUENCE {
    a INTEGER,
    b INTEGER
}
 */
static void test_bind_sequence()
{
  field_t parent = {0};
  parent.name = "Example";
  parent.value_type = SEQUENCE;
  parent.required = true;

  field_t field1 = {0};
  field1.name="a";
  field1.value_type=INTEGER;
  field1.required=true;

  field_t field2 = {0};
  field2.name="b";
  field2.value_type=INTEGER;
  field2.required=true;

  add_field(&parent,&field1);
  add_field(&parent,&field2);

  uint8_t buf[]={0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x02};

  tlv_t actual = parse_tlv(buf, ARRAY_LEN(buf));
  tlv_node_t *tlv_root = build_tlv(actual);
  bool is_valid = validate_asn1(&parent, tlv_root);
  TEST_ASSERT_EQUAL(true, is_valid);
  field_value_t *value=NULL;
  bind_schema(&parent,tlv_root,&value);

  TEST_ASSERT_EQUAL_PTR(value->field,&parent);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->tlv,&tlv_root->children[0]);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->field,&field1);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->tlv,&tlv_root->children[1]);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->field,&field2);
}

/*
Example ::= SEQUENCE {
    a INTEGER,
    b INTEGER OPTIONAL,
    c INTEGER
}
*/
static void test_bind_sequence_with_optional()
{
  field_t parent = {0};
  parent.name = "Example";
  parent.value_type = SEQUENCE;
  parent.required = true;

  field_t field1 = {0};
  field1.name="a";
  field1.value_type=INTEGER;
  field1.required=true;

  field_t field2 = {0};
  field2.name="b";
  field2.value_type=INTEGER;
  field2.required=false;

  field_t field3 = {0};
  field3.name="c";
  field3.value_type=INTEGER;
  field3.required=true;

  add_field(&parent,&field1);
  add_field(&parent,&field2);
  add_field(&parent,&field3);

  uint8_t buf[]={0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x03};

  tlv_t actual = parse_tlv(buf, ARRAY_LEN(buf));
  tlv_node_t *tlv_root = build_tlv(actual);
  bool is_valid = validate_asn1(&parent, tlv_root);
  TEST_ASSERT_EQUAL(true, is_valid);
  field_value_t *value=NULL;
  bind_schema(&parent,tlv_root,&value);

  TEST_ASSERT_EQUAL_PTR(value->field,&parent);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->tlv,&tlv_root->children[0]);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->field,&field1);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->tlv,NULL);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->field,&field2);
  TEST_ASSERT_EQUAL_PTR(value->children[2]->tlv,&tlv_root->children[1]);
  TEST_ASSERT_EQUAL_PTR(value->children[2]->field,&field3);
}

/*
Example ::= SEQUENCE {
    a INTEGER,
    b INTEGER DEFAULT 5,
    c INTEGER
}
*/
static void test_bind_sequence_with_default()
{
  field_t parent = {0};
  parent.name = "Example";
  parent.value_type = SEQUENCE;
  parent.required = true;

  field_t field1 = {0};
  field1.name="a";
  field1.value_type=INTEGER;
  field1.required=true;

  field_t field2 = {0};
  field2.name="b";
  field2.value_type=INTEGER;
  field2.required=true;
  field2.has_default=true;

  field_t field3 = {0};
  field3.name="c";
  field3.value_type=INTEGER;
  field3.required=true;

  add_field(&parent,&field1);
  add_field(&parent,&field2);
  add_field(&parent,&field3);

  uint8_t buf[]={0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x03};

  tlv_t actual = parse_tlv(buf, ARRAY_LEN(buf));
  tlv_node_t *tlv_root = build_tlv(actual);
  bool is_valid = validate_asn1(&parent, tlv_root);
  TEST_ASSERT_EQUAL(true, is_valid);
  field_value_t *value=NULL;
  bind_schema(&parent,tlv_root,&value);

  TEST_ASSERT_EQUAL_PTR(value->field,&parent);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->tlv,&tlv_root->children[0]);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->field,&field1);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->tlv,NULL);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->field,&field2);
  TEST_ASSERT_EQUAL_PTR(value->children[2]->tlv,&tlv_root->children[1]);
  TEST_ASSERT_EQUAL_PTR(value->children[2]->field,&field3);
}

/*
Example ::= CHOICE {
    a INTEGER,
    b OCTET STRING
}
*/
static void test_bind_choice()
{
  field_t parent = {0};
  parent.name = "Example";
  parent.value_type = CHOICE;
  parent.required = true;

  field_t field1 = {0};
  field1.name="a";
  field1.value_type=INTEGER;
  field1.required=true;

  field_t field2 = {0};
  field2.name="b";
  field2.value_type=OCTET_STRING;
  field2.required=true;

  add_field(&parent,&field1);
  add_field(&parent,&field2);

  uint8_t buf[]={0x02,0x01,0x05};

  tlv_t actual = parse_tlv(buf, ARRAY_LEN(buf));
  tlv_node_t *tlv_root = build_tlv(actual);
  bool is_valid = validate_asn1(&parent, tlv_root);
  TEST_ASSERT_EQUAL(true, is_valid);
  field_value_t *value=NULL;
  bind_schema(&parent,tlv_root,&value);

  TEST_ASSERT_EQUAL_PTR(value->field,&parent);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->field,&field1);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->tlv,tlv_root);
}

/*
Example ::= CHOICE {
    a INTEGER,
    b SEQUENCE {
        x INTEGER,
        y INTEGER
    }
}
*/
static void test_bind_choice_with_sequence()
{
  field_t parent = {0};
  parent.name = "Example";
  parent.value_type = CHOICE;
  parent.required = true;

  field_t field1 = {0};
  field1.name="a";
  field1.value_type=INTEGER;
  field1.required=true;

  field_t field2 = {0};
  field2.name="b";
  field2.value_type=SEQUENCE;
  field2.required=true;

  field_t field3 = {0};
  field3.name="x";
  field3.value_type=INTEGER;
  field3.required=true;

  field_t field4 = {0};
  field4.name="y";
  field4.value_type=INTEGER;
  field4.required=true;

  add_field(&parent,&field1);
  add_field(&parent,&field2);

  add_field(&field2,&field3);
  add_field(&field2,&field4);

  uint8_t buf[]={0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x02};

  tlv_t actual = parse_tlv(buf, ARRAY_LEN(buf));
  tlv_node_t *tlv_root = build_tlv(actual);
  bool is_valid = validate_asn1(&parent, tlv_root);
  TEST_ASSERT_EQUAL(true, is_valid);
  field_value_t *value=NULL;
  bind_schema(&parent,tlv_root,&value);

  TEST_ASSERT_EQUAL_PTR(value->field,&parent);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->field,&field2);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->tlv,tlv_root);
}

/*
Example ::= CHOICE {
    a [0] EXPLICIT INTEGER,
    b [1] EXPLICIT INTEGER
}
*/
static void test_bind_choice_with_explicit()
{
  field_t parent = {0};
  parent.name = "Example";
  parent.value_type = CHOICE;
  parent.required = true;

  field_t field1 = {0};
  field1.name="a";
  field1.value_type=INTEGER;
  field1.encoding_type=EXPLICIT;
  field1.match_type=TAG;
  field1.tag_number=0;
  field1.required=true;
  field1.tag_class=CONTEXT_SPECIFIC;

  field_t field2 = {0};
  field2.name="b";
  field2.value_type=INTEGER;
  field2.encoding_type=EXPLICIT;
  field2.match_type=TAG;
  field2.tag_number=1;
  field2.tag_class=CONTEXT_SPECIFIC;
  field2.required=true;

  add_field(&parent,&field1);
  add_field(&parent,&field2);

  uint8_t buf[]={0xA1,0x03,0x02,0x01,0x05};

  tlv_t actual = parse_tlv(buf, ARRAY_LEN(buf));
  tlv_node_t *tlv_root = build_tlv(actual);
  bool is_valid = validate_asn1(&parent, tlv_root);
  TEST_ASSERT_EQUAL(true, is_valid);
  field_value_t *value=NULL;
  bind_schema(&parent,tlv_root,&value);

  TEST_ASSERT_EQUAL_PTR(value->field,&parent);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->field,&field2);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->tlv,tlv_root);
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
  RUN_TEST(test_validate_nested_fields);
  RUN_TEST(test_validate_sequence_of);
  RUN_TEST(test_validate_set);
  RUN_TEST(test_bind_sequence);
  RUN_TEST(test_bind_sequence_with_optional);
  RUN_TEST(test_bind_sequence_with_default);
  RUN_TEST(test_bind_choice);
  RUN_TEST(test_bind_choice_with_sequence);
  RUN_TEST(test_bind_choice_with_explicit);
  return UNITY_END();
}
