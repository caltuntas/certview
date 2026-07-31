#include <string.h>
#include "x509.h"

/*
https://www.ietf.org/rfc/rfc3279.txt
ECDSA-Sig-Value ::= SEQUENCE {
    r     INTEGER,
    s     INTEGER 
}
*/
field_t *x509_ecdsa_sig_value()
{
  field_t *field_ecdsa =calloc(1,sizeof(field_t));
  field_ecdsa->name = "ECDSA-Sig-Value";
  field_ecdsa->value_type = SEQUENCE;
  field_ecdsa->pc = CONSTRUCTED;
  field_ecdsa->required = true;

  field_t *field_r=calloc(1,sizeof(field_t));
  field_r->name = "r";
  field_r->value_type = INTEGER;
  field_r->required = true;

  field_t *field_s=calloc(1,sizeof(field_t));
  field_s->name = "s";
  field_s->value_type = INTEGER;
  field_s->required = true;

  add_field(field_ecdsa,field_r);
  add_field(field_ecdsa,field_s);

  return field_ecdsa;
}

algorithm_identifier_t *x509_create_algorithm_identifier_from_asn1(field_value_t *root)
{
  algorithm_identifier_t *alg=malloc(sizeof(*alg));
  alg->algorithm_id=root->children[0]->value.oid;
  return alg;
}

certificate_t *x509_create_from_asn1(field_value_t *root)
{
  certificate_t *cert=malloc(sizeof(*cert));
  cert->tbsCertificate=malloc(sizeof(tbs_certificate_t));
  cert->signatureValue=malloc(sizeof(signature_t));
  cert->tbsCertificate->subjectPublicKeyInfo=malloc(sizeof(subject_public_key_info_t));
  cert->tbsCertificate->subjectPublicKeyInfo->algorithm=malloc(sizeof(algorithm_identifier_t));
  cert->tbsCertificate->subjectPublicKeyInfo->subject_public_key=malloc(sizeof(subject_public_key_t));

  field_value_t *tbsCertNode=find_child_value(root,"TBSCertificate"); 
  field_value_t *versionNode=find_child_value(tbsCertNode,"version"); 
  field_value_t *spkiNode=find_child_value(tbsCertNode,"SubjectPublicKeyInfo"); 
  field_value_t *algorithmIdentifierNode=find_child_value(spkiNode,"AlgorithmIdentifier"); 
  field_value_t *algorithmNode=find_child_value(algorithmIdentifierNode,"algorithm"); 
  field_value_t *paramsNode=find_child_value(algorithmIdentifierNode,"parameters"); 
  field_value_t *subjectPubKeyNode=find_child_value(spkiNode,"subjectPublicKey"); 
  cert->tbsCertificate->subjectPublicKeyInfo->algorithm->algorithm_id=algorithmNode->value.oid;
  char *spki_alg_id =oid_to_str(cert->tbsCertificate->subjectPublicKeyInfo->algorithm->algorithm_id);
  if(strcmp(spki_alg_id,"1.2.840.10045.2.1")==0) {
    cert->tbsCertificate->subjectPublicKeyInfo->algorithm->alg_type=ALG_TYPE_EC;
    cert->tbsCertificate->subjectPublicKeyInfo->algorithm->parameters.ec_curve_id=paramsNode->value.oid;
    char *curve_id_str=oid_to_str(cert->tbsCertificate->subjectPublicKeyInfo->algorithm->parameters.ec_curve_id);
    char *b=curve_id_str;

    cert->tbsCertificate->subjectPublicKeyInfo->subject_public_key->bit_string=subjectPubKeyNode->value.bitstring;
    bit_string_t *bitstr=subjectPubKeyNode->value.bitstring;
    //https://datatracker.ietf.org/doc/html/rfc5480#section-2.2
    if(bitstr->data[1]==0x04) {
      cert->tbsCertificate->subjectPublicKeyInfo->subject_public_key->public_key.ec_point=malloc(sizeof(ecdsa_point_t));
      cert->tbsCertificate->subjectPublicKeyInfo->subject_public_key->public_key.ec_point->x=create_bigint_unsigned(bitstr->data+2,32);
      cert->tbsCertificate->subjectPublicKeyInfo->subject_public_key->public_key.ec_point->y=create_bigint_unsigned(bitstr->data+34,32);
    }
  }
  int version=bigint_convert_to_int(versionNode->value.bigint);
  cert->tbsCertificate->version=version;
  cert->tbsCertificate->value=tbsCertNode->tlv->tlv.start;
  cert->tbsCertificate->value_len=tbsCertNode->tlv->tlv.len+tbsCertNode->tlv->tlv.len_meta;
  field_value_t *signatureAlgorithmNode=find_child_value(root,"AlgorithmIdentifier"); 
  field_value_t *signatureNode=find_child_value(root,"signatureValue"); 
  cert->signatureValue->bitstring=signatureNode->value.bitstring;
  cert->signatureAlgorithm=x509_create_algorithm_identifier_from_asn1(signatureAlgorithmNode);
  char *alg_id =oid_to_str(cert->signatureAlgorithm->algorithm_id);
  if(strcmp(alg_id,"1.2.840.10045.4.3.2")==0) {
    field_t *field_ecdsa_sig=x509_ecdsa_sig_value();
    field_value_t *out=NULL;
    uint8_t *buf=signatureNode->value.bitstring->data;
    tlv_t actual = parse_tlv(buf+1,signatureNode->tlv->tlv.len-1);
    tlv_node_t *root = build_tlv(actual);
    bool is_valid=validate_schema(field_ecdsa_sig,root,&out);
    if(is_valid){
      field_value_t *rfv=find_child_value(out,"r"); 
      field_value_t *sfv=find_child_value(out,"s"); 
      decode(rfv,NULL);
      decode(sfv,NULL);
      cert->signatureValue->signature.ecdsa.r=rfv->value.bigint;
      cert->signatureValue->signature.ecdsa.s=sfv->value.bigint;
    }
  }
  return cert;
}
