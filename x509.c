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
  alg->algorithm=root->children[0]->value.oid;
  return alg;
}

certificate_t *x509_create_from_asn1(field_value_t *root)
{
  certificate_t *cert=malloc(sizeof(*cert));
  cert->tbsCertificate=malloc(sizeof(tbs_certificate_t));
  cert->signatureValue=malloc(sizeof(signature_t));

  field_value_t *tbsCertNode=find_child_value(root,"TBSCertificate"); 
  field_value_t *versionNode=find_child_value(tbsCertNode,"version"); 
  int version=bigint_convert_to_int(versionNode->value.bigint);
  cert->tbsCertificate->version=version;
  cert->tbsCertificate->value=tbsCertNode->tlv->tlv.start;
  cert->tbsCertificate->value_len=tbsCertNode->tlv->tlv.len+tbsCertNode->tlv->tlv.len_meta;
  field_value_t *signatureAlgorithmNode=find_child_value(root,"AlgorithmIdentifier"); 
  field_value_t *signatureNode=find_child_value(root,"signatureValue"); 
  cert->signatureValue->bitstring=signatureNode->value.bitstring;
  cert->signatureAlgorithm=x509_create_algorithm_identifier_from_asn1(signatureAlgorithmNode);
  char *alg_id =oid_to_str(cert->signatureAlgorithm->algorithm);
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
