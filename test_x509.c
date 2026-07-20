#include "test-framework/unity.h"
#include "test_custom_assertions.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "x509.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))
#define BIGINT(sign,...) (bigint_t){sign,(uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__})}

void setUp(void)
{
}

void tearDown(void)
{
}

static void test_create_x509_certificate_from_asn1()
{
	char* file_name="example.der";

	uint8_t *buffer;
	size_t len;
	FILE *file =fopen(file_name,"rb");
	if(file==NULL) {
		perror("fopen");
		return ;
	}

	fseek(file,0,SEEK_END);
	len=ftell(file);
	fseek(file,0,SEEK_SET);
	buffer=malloc(len);
	if(buffer==NULL) {
		perror("malloc");
		fclose(file);
		return ;
	}
	fread(buffer,1,len,file);
	fclose(file);

	tlv_t tlv = parse_tlv(buffer,len);
	tlv_node_t *root =build_tlv(tlv);
	field_t *parent=create_x509_definition();

	field_value_t *mapping=NULL;
	bool is_valid=validate_schema(parent,root,&mapping);
	TEST_ASSERT_TRUE(is_valid);

	decode(mapping,NULL);
	certificate_t *cert=x509_create_from_asn1(mapping);
	TEST_ASSERT_EQUAL_INT(2,cert->tbsCertificate->version);
  bigint_t r=BIGINT(1,0x76,0x3C,0x5C,0x11,0xA6,0xF5,0x10,0xE9,0xBD,0x49,0x03,0x9E,0x64,0xC0,0x0D,0xF7,0xBF,0x20,0x9A,0xC3,0x57,0xFB,0xF0,0x28,0x1E,0x68,0x34,0x42,0x9B,0xDB,0x1E,0x31);
  bigint_t s=BIGINT(1,0x7C,0x39,0x2F,0x03,0x88,0x9D,0x87,0xEA,0x97,0x3F,0xCC,0xA6,0xEB,0x75,0x7F,0xA0,0x2D,0x4E,0x02,0xD7,0x90,0xEC,0x82,0x08,0x7F,0xDA,0xFD,0xB1,0x4A,0x83,0xDD,0x20);
  TEST_ASSERT_BIGINT_EQUAL(&r,cert->signatureValue->signature.ecdsa.r);
  TEST_ASSERT_BIGINT_EQUAL(&s,cert->signatureValue->signature.ecdsa.s);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_create_x509_certificate_from_asn1);
  return UNITY_END();
}
