#include "test-framework/unity.h"
#include "test_custom_assertions.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "x509.h"
#include "sha256.h"
#include "ecdsa.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))
#define BIGINT(sign,...) (bigint_t){sign,(uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__})}

void setUp(void)
{
}

void tearDown(void)
{
}

uint8_t *read_file(char *file_name,size_t *len)
{
	uint8_t *buffer;
	FILE *file =fopen(file_name,"rb");
	if(file==NULL) {
		perror("fopen");
		return NULL ;
	}
	fseek(file,0,SEEK_END);
	*len=ftell(file);
	fseek(file,0,SEEK_SET);
	buffer=malloc(*len);
	if(buffer==NULL) {
		perror("malloc");
		fclose(file);
		return NULL;
	}
	fread(buffer,1,*len,file);
	fclose(file);
  return buffer;
}

static void test_create_x509_certificate_from_asn1()
{
	char* leaf_cert_file="example.der";
	char* intermediate_cert_file="cloudflare.der";

  size_t len;
	uint8_t *leaf_cert_buffer=read_file("example.der",&len);
	tlv_t tlv = parse_tlv(leaf_cert_buffer,len);
	tlv_node_t *root =build_tlv(tlv);
	field_t *parent=create_x509_definition();

  size_t intermediate_len;
	uint8_t *intermediate_cert_buffer=read_file("cloudflare.der",&intermediate_len);
	tlv_t inm_tlv = parse_tlv(intermediate_cert_buffer,intermediate_len);
	tlv_node_t *inm_root =build_tlv(inm_tlv);
	field_t *inm_parent=create_x509_definition();

	field_value_t *mapping=NULL;
	bool is_valid=validate_schema(parent,root,&mapping);
	TEST_ASSERT_TRUE(is_valid);

	field_value_t *inm_mapping=NULL;
	is_valid=validate_schema(inm_parent,inm_root,&inm_mapping);
	TEST_ASSERT_TRUE(is_valid);

	decode(mapping,NULL);
	certificate_t *leaf_cert=x509_create_from_asn1(mapping);

	decode(inm_mapping,NULL);
	certificate_t *inm_cert=x509_create_from_asn1(inm_mapping);

	TEST_ASSERT_EQUAL_INT(2,leaf_cert->tbsCertificate->version);
  bigint_t r=BIGINT(1,0x76,0x3C,0x5C,0x11,0xA6,0xF5,0x10,0xE9,0xBD,0x49,0x03,0x9E,0x64,0xC0,0x0D,0xF7,0xBF,0x20,0x9A,0xC3,0x57,0xFB,0xF0,0x28,0x1E,0x68,0x34,0x42,0x9B,0xDB,0x1E,0x31);
  bigint_t s=BIGINT(1,0x7C,0x39,0x2F,0x03,0x88,0x9D,0x87,0xEA,0x97,0x3F,0xCC,0xA6,0xEB,0x75,0x7F,0xA0,0x2D,0x4E,0x02,0xD7,0x90,0xEC,0x82,0x08,0x7F,0xDA,0xFD,0xB1,0x4A,0x83,0xDD,0x20);
  TEST_ASSERT_BIGINT_EQUAL(&r,leaf_cert->signatureValue->signature.ecdsa.r);
  TEST_ASSERT_BIGINT_EQUAL(&s,leaf_cert->signatureValue->signature.ecdsa.s);
  uint8_t expected_hash[]={
    0x38,0xE6,0xDF,0xDC,0x8E,0xE5,0x86,0x90, 0xC6,0x68,0xEB,0x3F,0x63,0x69,0x3B,0x18, 0x29,0x75,0xD8,0x4C,0xCC,0xBF,0x02,0x64, 0x4F,0xF9,0x91,0x58,0x82,0x28,0x6C,0x19
  };
  uint8_t hash[32]={0};
  sha256_hash(leaf_cert->tbsCertificate->value,leaf_cert->tbsCertificate->value_len,hash);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_hash,hash,32);
  char *curve_id_str=oid_to_str(leaf_cert->tbsCertificate->subjectPublicKeyInfo->algorithm->parameters.ec_curve_id);
  ecdsa_params_t params;
  if(strcmp(curve_id_str,"1.2.840.10045.3.1.7")==0) {
    params=ecdsa_params[PRIME256V1];
  }
  ecdsa_signature_t sig = {
    .r=&r,
    .s=&s
  };
  ecdsa_point_t issuer_q = {
    inm_cert->tbsCertificate->subjectPublicKeyInfo->subject_public_key->public_key.ec_point->x,
    inm_cert->tbsCertificate->subjectPublicKeyInfo->subject_public_key->public_key.ec_point->y
  };
  bigint_t *z = create_bigint(hash,32);
  bool valid =
    ecdsa_signature_verify(
      params,
      sig,
      z,
      issuer_q
    );
  TEST_ASSERT_TRUE(valid);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_create_x509_certificate_from_asn1);
  return UNITY_END();
}
