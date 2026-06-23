#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "asn1.h"
#include "x509.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))

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
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_create_x509_certificate_from_asn1);
  return UNITY_END();
}
