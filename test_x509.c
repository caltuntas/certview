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

void print_debug(bool valid, uint8_t *data,size_t data_len,tlv_node_t *node,field_t *field, field_value_t *value)
{
  static int counter=1;
  printf("#######Case %d############\n",counter++);
  printf("---ASN1 Definition---\n");
  print_field(field,0);
  printf("\n");
  printf("---Raw Data---\n");
  print_data(data,data_len);
  printf("\n");
  printf("---Parsed Der---\n");
  print_tlv_node(node,0);
  if(valid){
    printf("\n");
    printf("---Mapped Values---\n");
    print_field_value(value,0);
    printf("\n");
  } else {
    printf("\n");
    printf("---Mapped Values---\n");
    printf("Invalid structure!\n");
  }
  printf("#######################\n");
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
  parent_field.pc=CONSTRUCTED;
  parent_field.required=true;

  field_t field1={0};	
  field1.name="algorithm";
  field1.value_type=OBJECT_IDENTIFIER;
  field1.required=true;

  field_t field2={0};	
  field2.name="parameters";
  field2.value_type=ANY;
  field2.required=false;

  add_field(&parent_field,&field1);
  add_field(&parent_field,&field2);

  TEST_ASSERT_EQUAL_INT(2,parent_field.count);
}

static void test_oid_only(void)
{
  field_t parent_field={0};	
  parent_field.name="AlgorithmIdentifier";
  parent_field.value_type=SEQUENCE;
  parent_field.pc=CONSTRUCTED;
  parent_field.tag_class=UNIVERSAL;
  parent_field.required=true;

  field_t field1={0};	
  field1.name="algorithm";
  field1.value_type=OBJECT_IDENTIFIER;
  field1.tag_class=UNIVERSAL;
  field1.required=true;

  field_t field2={0};	
  field2.name="parameters";
  field2.value_type=ANY;
  field2.required=false;

  add_field(&parent_field,&field1);
  add_field(&parent_field,&field2);

  uint8_t buf[]={0x30,0x0A,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
  size_t len=ARRAY_LEN(buf);
  tlv_t actual = parse_tlv(buf,len);
  tlv_node_t *root =build_tlv(actual);

  field_value_t *out=NULL;
  bool is_valid=validate_schema(&parent_field,root,&out);
  print_debug(is_valid,buf,len,root,&parent_field,out);

  TEST_ASSERT_TRUE(is_valid);
}

static void test_invalid_null_first(void)
{
  field_t parent_field={0};	
  parent_field.name="AlgorithmIdentifier";
  parent_field.value_type=SEQUENCE;
  parent_field.pc=CONSTRUCTED;
  parent_field.required=true;

  field_t field1={0};	
  field1.name="algorithm";
  field1.value_type=OBJECT_IDENTIFIER;
  field1.required=true;

  field_t field2={0};	
  field2.name="parameters";
  field2.value_type=ANY;
  field2.required=false;

  add_field(&parent_field,&field1);
  add_field(&parent_field,&field2);

  uint8_t buf[]={0x30,0x0C,0x05,0x00,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
  size_t len=ARRAY_LEN(buf);
  tlv_t actual = parse_tlv(buf,len);
  tlv_node_t *root =build_tlv(actual);

  field_value_t *out=NULL;
  bool is_valid=validate_schema(&parent_field,root,&out);
  print_debug(is_valid,buf,len,root,&parent_field,out);

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
  parent_field.pc=CONSTRUCTED;
  parent_field.tag_class=UNIVERSAL;
  parent_field.required=true;

  field_t field1={0};	
  field1.name="algorithm";
  field1.value_type=OBJECT_IDENTIFIER;
  field1.tag_class=UNIVERSAL;
  field1.required=true;

  field_t field2={0};	
  field2.name="parameters";
  field2.value_type=ANY;
  field2.required=false;

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
    field_value_t *out=NULL;
    bool is_valid=validate_schema(&parent_field,root,&out);
    print_debug(is_valid,tc.data,tc.len,root,&parent_field,out);
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
  parent_field.pc=CONSTRUCTED;
  parent_field.required=true;

  field_t field1={0};	
  field1.name="version";
  field1.tag_number=0;
  field1.tag_class=CONTEXT_SPECIFIC;
  field1.required=false;
  field1.encoding_type=EXPLICIT;
  field1.value_type=INTEGER;
  field1.has_default=true;

  field_t field2={0};	
  field2.name="serialNumber";
  field2.tag_class=UNIVERSAL;
  field2.value_type=INTEGER;
  field2.required=true;

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
    field_value_t *out=NULL;
    bool is_valid=validate_schema(&parent_field,root,&out);
    print_debug(is_valid,tc.data,tc.len,root,&parent_field,out);
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
  parent_field.pc=CONSTRUCTED;
  parent_field.required=true;

  field_t field1={0};	
  field1.name="serialNumber";
  field1.tag_class=UNIVERSAL;
  field1.value_type=INTEGER;
  field1.required=true;

  field_t field2={0};	
  field2.name="issuerUniqueID";
  field2.tag_class=CONTEXT_SPECIFIC;
  field2.tag_number=1;
  field2.required=false;
  field2.encoding_type=IMPLICIT;
  field2.value_type=BIT_STRING;

  field_t field3={0};	
  field3.name="subjectUniqueID";
  field3.tag_class=CONTEXT_SPECIFIC;
  field3.tag_number=2;
  field3.required=false;
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
    field_value_t *out=NULL;
    bool is_valid=validate_schema(&parent_field,root,&out);
    print_debug(is_valid,tc.data,tc.len,root,&parent_field,out);
    TEST_ASSERT_EQUAL_MESSAGE(tc.result,is_valid,msg);
  }
}

/*
TestImplicit ::= SEQUENCE {
  id        INTEGER,
  payload   [0] IMPLICIT Payload OPTIONAL
}
Payload ::= SEQUENCE {
  flag      BOOLEAN,
  value     INTEGER
}
*/
static void test_validate_implicit_sequence(void) 
{
  field_t parent_field={0};	
  parent_field.name="TestImplicit";
  parent_field.tag_class=UNIVERSAL;
  parent_field.value_type=SEQUENCE;
  parent_field.pc=CONSTRUCTED;
  parent_field.required=true;

  field_t field1={0};	
  field1.name="id";
  field1.tag_class=UNIVERSAL;
  field1.value_type=INTEGER;
  field1.required=true;

  field_t field2={0};	
  field2.name="payload";
  field2.tag_class=CONTEXT_SPECIFIC;
  field2.tag_number=0;
  field2.required=false;
  field2.encoding_type=IMPLICIT;
  field2.value_type=REFERENCE_TYPE;
  field2.reference_type="Payload";

  field_t payload={0};	
  payload.name="Payload";
  payload.tag_class=UNIVERSAL;
  payload.value_type=SEQUENCE;
  payload.pc=CONSTRUCTED;

  field_t payload_flag = {0};
  payload_flag.name = "flag";
  payload_flag.tag_class=UNIVERSAL;
  payload_flag.value_type = BOOLEAN;
  payload_flag.required = true;


  field_t payload_value = {0};
  payload_value.name = "value";
  payload_value.tag_class=UNIVERSAL;
  payload_value.value_type = INTEGER;
  payload_value.required = true;


  add_field(&parent_field,&field1);
  add_field(&parent_field,&field2);

  add_field(&payload,&payload_flag);
  add_field(&payload,&payload_value);

  add_field(&field2,&payload);

  test_case cases[]={
    CASE(true,0x30,0x03,0x02,0x01,0x05),
    CASE(true,0x30,0x0B,0x02,0x01,0x05,0xA0,0x06,0x01,0x01,0xFF,0x02,0x01,0x2A),
  };

  int len = ARRAY_LEN(cases);
  for (int i=0; i<len; i++) {
    test_case tc=cases[i];
    tlv_t actual = parse_tlv(tc.data,tc.len);
    tlv_node_t *root =build_tlv(actual);
    char msg[40]={0};
    snprintf(msg,20,"case=%d\n",i);
    field_value_t *out=NULL;
    bool is_valid=validate_schema(&parent_field,root,&out);
    print_debug(is_valid,tc.data,tc.len,root,&parent_field,out);
    TEST_ASSERT_EQUAL_MESSAGE(tc.result,is_valid,msg);
  }
}

/*
TestExplicit ::= SEQUENCE {
  id        INTEGER,
  payload   [0] EXPLICIT Payload OPTIONAL
}

Payload ::= SEQUENCE {
  flag      BOOLEAN,
  value     INTEGER
}
 */
static void test_validate_explicit_sequence(void)
{
  field_t parent_field={0};
  parent_field.name="TestExplicit";
  parent_field.tag_class=UNIVERSAL;
  parent_field.value_type=SEQUENCE;
  parent_field.pc=CONSTRUCTED;
  parent_field.required=true;

  field_t field1={0};
  field1.name="id";
  field1.tag_class=UNIVERSAL;
  field1.value_type=INTEGER;
  field1.required=true;

  field_t field2={0};
  field2.name="payload";
  field2.tag_class=CONTEXT_SPECIFIC;
  field2.tag_number=0;
  field2.required=false;
  field2.encoding_type=EXPLICIT;
  field2.value_type=REFERENCE_TYPE;
  field2.reference_type="Payload";

  field_t payload={0};
  payload.name="Payload";
  payload.tag_class=UNIVERSAL;
  payload.value_type=SEQUENCE;
  payload.pc=CONSTRUCTED;

  field_t payload_flag={0};
  payload_flag.name="flag";
  payload_flag.tag_class=UNIVERSAL;
  payload_flag.value_type=BOOLEAN;
  payload_flag.required=true;

  field_t payload_value={0};
  payload_value.name="value";
  payload_value.tag_class=UNIVERSAL;
  payload_value.value_type=INTEGER;
  payload_value.required=true;

  add_field(&parent_field,&field1);
  add_field(&parent_field,&field2);

  add_field(&payload,&payload_flag);
  add_field(&payload,&payload_value);

  add_field(&field2,&payload);

  test_case cases[]={
    CASE(true,0x30,0x03,0x02,0x01,0x05),
    CASE(true,0x30,0x0D,0x02,0x01,0x05,0xA0,0x08,0x30,0x06,0x01,0x01,0xFF,0x02,0x01,0x2A),
    CASE(false,0x30,0x0A,0x02,0x01,0x05,0x80,0x05,0x30,0x03,0x01,0x01,0xFF),
    CASE(false,0x30,0x08,0x02,0x01,0x05,0xA0,0x03,0x02,0x01,0x2A),
    CASE(false,0x30,0x0B,0x02,0x01,0x05,0xA0,0x06,0x01,0x01,0xFF,0x02,0x01,0x2A),
    CASE(false,0x30,0x0A,0x02,0x01,0x05,0xA0,0x05,0x30,0x04,0x01,0x01,0xFF),
    CASE(false,0x30,0x0D,0x02,0x01,0x05,0xA0,0x08,0x30,0x06,0x02,0x01,0x2A,0x01,0x01,0xFF),
    CASE(false,0x30,0x0D,0x02,0x01,0x05,0xA1,0x08,0x30,0x06,0x01,0x01,0xFF,0x02,0x01,0x2A),
  };

  int len = ARRAY_LEN(cases);
  for (int i=0; i<len; i++) {
    test_case tc=cases[i];
    tlv_t actual=parse_tlv(tc.data,tc.len);
    tlv_node_t *root=build_tlv(actual);

    char msg[40]={0};
    snprintf(msg,20,"case=%d\n",i);

    field_value_t *out=NULL;
    bool is_valid=validate_schema(&parent_field,root,&out);
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
  parent_field.pc=CONSTRUCTED;
  parent_field.required=true;

  field_t field1={0};	
  field1.name="foo";
  field1.tag_class=UNIVERSAL;
  field1.value_type=INTEGER;
  field1.required=true;

  field_t field2 = {0};
  field2.name = "bar";
  field2.value_type = CHOICE;
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
  option3.pc=CONSTRUCTED;
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
    field_value_t *out=NULL;
    bool is_valid=validate_schema(&parent_field,root,&out);
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
  algo_field.pc=CONSTRUCTED;
  algo_field.pc=CONSTRUCTED;
  algo_field.required=true;

  field_t field1={0};	
  field1.name="algorithm";
  field1.value_type=OBJECT_IDENTIFIER;
  field1.required=true;

  field_t field2={0};	
  field2.name="parameters";
  field2.value_type=ANY;
  field2.required=false;

  field_t parent_field={0};	
  parent_field.name="SubjectPublicKeyInfo";
  parent_field.value_type=SEQUENCE;
  parent_field.pc=CONSTRUCTED;
  parent_field.required=true;

  field_t field4={0};	
  field4.name="algorithm";
  field4.value_type=REFERENCE_TYPE;
  field4.reference_type="AlgorithmIdentifier";
  field4.required=true;

  field_t field3={0};	
  field3.name="subjectPublicKey";
  field3.tag_class=UNIVERSAL;
  field3.required=true;
  field3.value_type=BIT_STRING;

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
    field_value_t *out=NULL;
    bool is_valid=validate_schema(&parent_field,root,&out);
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
  parent.pc=CONSTRUCTED;
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
    field_value_t *out=NULL;
    bool is_valid = validate_schema(&parent, root,&out);
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
  parent.pc=CONSTRUCTED;
  parent.required = true;
  parent.element_type = REFERENCE_TYPE;
  parent.reference_type = "RelativeDistinguishedName";

  field_t field1 = {0};
  field1.name="RelativeDistinguishedName";
  field1.value_type=SET;
  field1.pc=CONSTRUCTED;
  field1.element_type=REFERENCE_TYPE;
  field1.reference_type="AttributeTypeAndValue";

  field_t field2={0};
  field2.name="AttributeTypeAndValue";
  field2.value_type=SEQUENCE;
  field2.pc=CONSTRUCTED;
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
    field_value_t *out=NULL;
    bool is_valid = validate_schema(&parent, root,&out);
    if(is_valid!=tc.result){
      print_field(&parent,0);
      print_tlv_node(root,0);
    }
    TEST_ASSERT_EQUAL_MESSAGE(tc.result, is_valid, msg);
  }
}

/*
   FinalTest ::= SEQUENCE {
   version         [0] EXPLICIT INTEGER DEFAULT 1,
   identifier      INTEGER,
   payload         Payload,
   attributes      SEQUENCE OF Attribute OPTIONAL
   }
   Payload ::= CHOICE {
   simple          INTEGER,
   complex         [1] IMPLICIT ComplexPayload
   }
   ComplexPayload ::= SEQUENCE {
   flag            BOOLEAN,
   values          SEQUENCE OF INTEGER,
   extra           [2] EXPLICIT UTF8String OPTIONAL
   }
   Attribute ::= SEQUENCE {
   type            OBJECT IDENTIFIER,
   value           AttributeValue
   }
   AttributeValue ::= CHOICE {
   intValue        INTEGER,
   strValue        UTF8String,
   binValue        OCTET STRING
   }
   */
static void test_validate_complex()
{
  field_t complex_payload = {0};
  complex_payload.name = "ComplexPayload";
  complex_payload.value_type = SEQUENCE;
  complex_payload.pc=CONSTRUCTED;
  complex_payload.required = true;

  field_t cp_flag = {0};
  cp_flag.name = "flag";
  cp_flag.value_type = BOOLEAN;
  cp_flag.required = true;

  field_t cp_values = {0};
  cp_values.name = "values";
  cp_values.value_type = SEQUENCE;
  cp_values.pc=CONSTRUCTED;
  cp_values.required = true;
  cp_values.element_type = REFERENCE_TYPE;

  field_t integer = {0};
  integer.value_type=INTEGER;
  integer.required=true;
  integer.has_default=false;

  add_field(&cp_values,&integer);


  field_t cp_extra = {0};
  cp_extra.name = "extra";
  cp_extra.tag_class = CONTEXT_SPECIFIC;
  cp_extra.tag_number = 2;
  cp_extra.encoding_type = EXPLICIT;
  cp_extra.value_type = UTF8String;
  cp_extra.required = false;

  add_field(&complex_payload, &cp_flag);
  add_field(&complex_payload, &cp_values);
  add_field(&complex_payload, &cp_extra);

  field_t payload = {0};
  payload.name = "Payload";
  payload.value_type = CHOICE;
  payload.required = true;

  field_t payload_simple = {0};
  payload_simple.name = "simple";
  payload_simple.value_type = INTEGER;

  field_t payload_complex = {0};
  payload_complex.name = "complex";
  payload_complex.tag_class = CONTEXT_SPECIFIC;
  payload_complex.tag_number = 1;
  payload_complex.encoding_type = IMPLICIT;
  payload_complex.value_type = REFERENCE_TYPE;
  payload_complex.reference_type = "ComplexPayload";

  add_field(&payload, &payload_simple);
  add_field(&payload, &payload_complex);

  add_field(&payload_complex, &complex_payload);

  field_t attribute_value = {0};
  attribute_value.name = "AttributeValue";
  attribute_value.value_type = CHOICE;
  attribute_value.required = true;

  field_t av_int = {0};
  av_int.name = "intValue";
  av_int.value_type = INTEGER;

  field_t av_str = {0};
  av_str.name = "strValue";
  av_str.value_type = UTF8String;

  field_t av_bin = {0};
  av_bin.name = "binValue";
  av_bin.value_type = OCTET_STRING;

  add_field(&attribute_value, &av_int);
  add_field(&attribute_value, &av_str);
  add_field(&attribute_value, &av_bin);

  field_t attribute = {0};
  attribute.name = "Attribute";
  attribute.value_type = SEQUENCE;
  attribute.pc=CONSTRUCTED;
  attribute.required = true;

  field_t attr_type = {0};
  attr_type.name = "type";
  attr_type.value_type = OBJECT_IDENTIFIER;
  attr_type.required = true;

  field_t attr_value = {0};
  attr_value.name = "value";
  attr_value.value_type = REFERENCE_TYPE;
  attr_value.reference_type = "AttributeValue";
  attr_value.required = true;

  add_field(&attribute, &attr_type);
  add_field(&attribute, &attr_value);

  add_field(&attr_value, &attribute_value);


  field_t final_test = {0};
  final_test.name = "FinalTest";
  final_test.value_type = SEQUENCE;
  final_test.pc=CONSTRUCTED;
  final_test.required = true;

  field_t ft_version = {0};
  ft_version.name = "version";
  ft_version.tag_class = CONTEXT_SPECIFIC;
  ft_version.tag_number = 0;
  ft_version.encoding_type = EXPLICIT;
  ft_version.value_type = INTEGER;
  ft_version.required = false;
  ft_version.has_default = true;

  field_t ft_identifier = {0};
  ft_identifier.name = "identifier";
  ft_identifier.value_type = INTEGER;
  ft_identifier.required = true;

  field_t ft_payload = {0};
  ft_payload.name = "payload";
  ft_payload.value_type = REFERENCE_TYPE;
  ft_payload.reference_type = "Payload";
  ft_payload.required = true;

  field_t ft_attributes = {0};
  ft_attributes.name = "attributes";
  ft_attributes.value_type = SEQUENCE;
  ft_attributes.pc=CONSTRUCTED;
  ft_attributes.element_type = REFERENCE_TYPE;
  ft_attributes.reference_type = "Attribute";
  ft_attributes.required = false;

  add_field(&final_test, &ft_version);
  add_field(&final_test, &ft_identifier);
  add_field(&final_test, &ft_payload);
  add_field(&final_test, &ft_attributes);

  add_field(&ft_attributes, &attribute);

  add_field(&ft_payload, &payload);

  test_case cases[] = {
    CASE(true,0x30,0x06,0x02,0x01,0x2A,0x02,0x01,0x05),
    CASE(true,0x30,0x0B,0xA0,0x03,0x02,0x01,0x02,0x02,0x01,0x2A,0x02,0x01,0x05),
    CASE(true,0x30,0x10,0x02,0x01,0x01,0xA1,0x0B,0x01,0x01,0xFF,0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x02),
  };

  int len = ARRAY_LEN(cases);
  for (int i = 0; i < len; i++) {
    test_case tc = cases[i];
    tlv_t actual = parse_tlv(tc.data, tc.len);
    tlv_node_t *root = build_tlv(actual);
    char msg[40] = {0};
    snprintf(msg, 20, "case=%d\n", i);
    field_value_t *out=NULL;
    bool is_valid = validate_schema(&final_test, root,&out);
    if(is_valid!=tc.result){
      print_field(&final_test,0);
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
  parent.pc=CONSTRUCTED;
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
  field_value_t *value=NULL;
  bool is_valid = validate_schema(&parent, tlv_root,&value);
  TEST_ASSERT_EQUAL(true, is_valid);

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
  parent.pc=CONSTRUCTED;
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
  field_value_t *value=NULL;
  bool is_valid = validate_schema(&parent, tlv_root,&value);
  TEST_ASSERT_EQUAL(true, is_valid);

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
  parent.pc=CONSTRUCTED;
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
  field_value_t *value=NULL;
  bool is_valid = validate_schema(&parent, tlv_root,&value);
  TEST_ASSERT_EQUAL(true, is_valid);

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
  field_value_t *value=NULL;
  bool is_valid = validate_schema(&parent, tlv_root,&value);
  TEST_ASSERT_EQUAL(true, is_valid);

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
  field2.pc=CONSTRUCTED;
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
  field_value_t *value=NULL;
  bool is_valid = validate_schema(&parent, tlv_root,&value);
  print_field(&parent,0);
  print_tlv_node(tlv_root,0);
  TEST_ASSERT_EQUAL(true, is_valid);

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
  field1.tag_number=0;
  field1.required=true;
  field1.tag_class=CONTEXT_SPECIFIC;

  field_t field2 = {0};
  field2.name="b";
  field2.value_type=INTEGER;
  field2.encoding_type=EXPLICIT;
  field2.tag_number=1;
  field2.tag_class=CONTEXT_SPECIFIC;
  field2.required=true;

  add_field(&parent,&field1);
  add_field(&parent,&field2);

  uint8_t buf[]={0xA1,0x03,0x02,0x01,0x05};

  tlv_t actual = parse_tlv(buf, ARRAY_LEN(buf));
  tlv_node_t *tlv_root = build_tlv(actual);
  field_value_t *value=NULL;
  bool is_valid = validate_schema(&parent, tlv_root,&value);
  TEST_ASSERT_EQUAL(true, is_valid);

  TEST_ASSERT_EQUAL_PTR(value->field,&parent);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->field,&field2);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->tlv,tlv_root);
}

/*
TestImplicit ::= SEQUENCE {
  id        INTEGER,
  payload   [0] IMPLICIT Payload OPTIONAL
}
Payload ::= SEQUENCE {
  flag      BOOLEAN,
  value     INTEGER
}
*/
static void test_bind_implicit_sequence(void) 
{
  field_t parent_field={0};	
  parent_field.name="TestImplicit";
  parent_field.tag_class=UNIVERSAL;
  parent_field.value_type=SEQUENCE;
  parent_field.pc=CONSTRUCTED;
  parent_field.required=true;

  field_t field1={0};	
  field1.name="id";
  field1.tag_class=UNIVERSAL;
  field1.value_type=INTEGER;
  field1.required=true;

  field_t field2={0};	
  field2.name="payload";
  field2.tag_class=CONTEXT_SPECIFIC;
  field2.tag_number=0;
  field2.required=false;
  field2.encoding_type=IMPLICIT;
  field2.value_type=REFERENCE_TYPE;
  field2.reference_type="Payload";

  field_t payload={0};	
  payload.name="Payload";
  payload.tag_class=UNIVERSAL;
  payload.value_type=SEQUENCE;
  payload.pc=CONSTRUCTED;

  field_t payload_flag = {0};
  payload_flag.name = "flag";
  payload_flag.tag_class=UNIVERSAL;
  payload_flag.value_type = BOOLEAN;
  payload_flag.required = true;


  field_t payload_value = {0};
  payload_value.name = "value";
  payload_value.tag_class=UNIVERSAL;
  payload_value.value_type = INTEGER;
  payload_value.required = true;


  add_field(&parent_field,&field1);
  add_field(&parent_field,&field2);

  add_field(&payload,&payload_flag);
  add_field(&payload,&payload_value);

  add_field(&field2,&payload);

  uint8_t buf[]={0x30,0x0B,0x02,0x01,0x05,0xA0,0x06,0x01,0x01,0xFF,0x02,0x01,0x2A};

  int len = ARRAY_LEN(buf);
  tlv_t actual = parse_tlv(buf,len);
  tlv_node_t *root =build_tlv(actual);
  field_value_t *value=NULL;
  bool is_valid=validate_schema(&parent_field,root,&value);
  print_debug(is_valid,buf,len,root,&parent_field,value);
  TEST_ASSERT_EQUAL(true,is_valid);

  TEST_ASSERT_EQUAL_PTR(value->field,&parent_field);
  TEST_ASSERT_EQUAL_INT(2,value->count);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->field,&field1);
  TEST_ASSERT_EQUAL_PTR(value->children[0]->tlv,&root->children[0]);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->field,&field2);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->tlv,&root->children[1]);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->children[0]->field,&payload_flag);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->children[0]->tlv,&root->children[1].children[0]);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->children[1]->field,&payload_value);
  TEST_ASSERT_EQUAL_PTR(value->children[1]->children[1]->tlv,&root->children[1].children[1]);
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
  RUN_TEST(test_validate_implicit_sequence);
  RUN_TEST(test_validate_explicit_sequence);
  RUN_TEST(test_validate_choice);
  RUN_TEST(test_validate_nested_fields);
  RUN_TEST(test_validate_sequence_of);
  RUN_TEST(test_validate_set);
  RUN_TEST(test_validate_complex);
  RUN_TEST(test_bind_sequence);
  RUN_TEST(test_bind_sequence_with_optional);
  RUN_TEST(test_bind_sequence_with_default);
  RUN_TEST(test_bind_choice);
  RUN_TEST(test_bind_choice_with_sequence);
  RUN_TEST(test_bind_choice_with_explicit);
  RUN_TEST(test_bind_implicit_sequence);
  return UNITY_END();
}
