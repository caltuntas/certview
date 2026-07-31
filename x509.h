#ifndef X509_H
#define X509_H

#include "oid.h"
#include "asn1.h"
#include "ecdsa.h"

typedef enum {
  ALG_TYPE_EC
} algorithm_type_t;

typedef struct signature_t {
  bit_string_t *bitstring;
  union {
    ecdsa_signature_t ecdsa;
  } signature;
} signature_t;

typedef struct extension_t {
	oid_t *extnID;
	bool *critical;
	void *extnValue;
} extension_t;

typedef struct attribute_t {
	oid_t *type;
	void *value;
} attribute_t;

typedef struct subject_public_key_t {
	bit_string_t *bit_string;
  union {
    ecdsa_point_t *ec_point;
  } public_key;
} subject_public_key_t;

typedef struct algorithm_identifier_t {
	oid_t *algorithm_id;
  algorithm_type_t alg_type;
	union {
    oid_t *ec_curve_id;
  } parameters;
} algorithm_identifier_t;

typedef struct subject_public_key_info_t {
	algorithm_identifier_t *algorithm;
	subject_public_key_t *subject_public_key;
} subject_public_key_info_t;

typedef struct tbs_certificate_t {
	int version;
  bigint_t *serialNumber;
	algorithm_identifier_t *signature;
	attribute_t **issuer;
	//validity
	attribute_t **subject;
  subject_public_key_info_t *subjectPublicKeyInfo;	
  uint8_t *value;
  size_t value_len;
} tbs_certificate_t;

typedef struct certificate_t {
	tbs_certificate_t *tbsCertificate;
	algorithm_identifier_t *signatureAlgorithm;
	signature_t *signatureValue;
} certificate_t;

certificate_t *x509_create_from_asn1(field_value_t *root);

#endif
