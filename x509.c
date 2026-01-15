#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "x509.h"


void add_field(field_t *parent, field_t *child)
{
  size_t cnt=parent->count;
  parent->children=realloc(parent->children,sizeof(field_t*)*(parent->count+1));
  parent->children[cnt]=child;
  parent->count+=1;
}

void add_field_value(field_value_t *parent, field_value_t *child)
{
  size_t cnt=parent->count;
  parent->children=realloc(parent->children,sizeof(field_t*)*(parent->count+1));
  parent->children[cnt]=child;
  parent->count+=1;
}

field_value_t* create_field_value(field_t *f, tlv_node_t *t)
{
  field_value_t *child=calloc(1,sizeof(field_value_t));
  if(f->parent && f->parent->value_type==REFERENCE_TYPE)
    child->field=f->parent;
  else
    child->field=f;
  child->tlv=t;
  return child;
}

field_t* create_field()
{
  field_t *f=calloc(1,sizeof(field_t));
  return f;
}

void create_add_field_value(field_value_t *parent, field_t *f, tlv_node_t *t)
{
  if(f->value_type!=REFERENCE_TYPE) {
    field_value_t *cv=create_field_value(f,t);
    add_field_value(parent,cv);
  }
}

void print_field(field_t *field,int indent) 
{
  const char *tag_number_str=tag_number_t_toString(field->value_type);
  char type_name[40]={0};
  if(field->value_type==REFERENCE_TYPE) 
    sprintf(type_name,"%s",field->children[0]->name);
  else
    sprintf(type_name,"%s",tag_number_str);
  char str[40]={0};
  if(field->tag_class==CONTEXT_SPECIFIC && field->encoding_type==EXPLICIT)
    sprintf(str,"[%d] EXPLICIT %s",field->tag_number,type_name);
  else if(field->tag_class ==CONTEXT_SPECIFIC && field->encoding_type==IMPLICIT)
    sprintf(str,"[%d] IMPLICIT %s",field->tag_number,type_name);
  else
    sprintf(str,"%s",type_name);

  if(field->element_type==REFERENCE_TYPE){
    strcat(str," OF");
  }
  if(field->required==false){
    strcat(str," OPTIONAL");
  }

  printf("%*s %s ::= %s ",indent,"",field->name,str);
  if(field->count > 0){
    printf("{");
  }
  printf("\n");
  for(int i=0; i<field->count; i++){
    print_field(field->children[i],indent+2);
  }
  if(field->count > 0){
    printf("%*s }\n",indent,"");
  }
}

void print_field_value(field_value_t *value,int indent) 
{
  //printf("\n\n");
  const char *tag_number_str=tag_number_t_toString(value->field->value_type);
  char type_name[40]={0};
  if(value->field->value_type==REFERENCE_TYPE) 
    sprintf(type_name,"%s",value->field->children[0]->name);
  else
    sprintf(type_name,"%s",tag_number_str);
  char str[40]={0};
  if(value->field->tag_class==CONTEXT_SPECIFIC && value->field->encoding_type==EXPLICIT){
    sprintf(str,"[%d] EXPLICIT %s",value->field->tag_number,type_name);
  }
  else if(value->field->tag_class ==CONTEXT_SPECIFIC && value->field->encoding_type==IMPLICIT)
    sprintf(str,"[%d] IMPLICIT %s",value->field->tag_number,type_name);
  else
    sprintf(str,"%s",type_name);

  if(value->field->element_type==REFERENCE_TYPE){
    strcat(str," OF");
  }
  if(value->field->required==false){
    strcat(str," OPTIONAL");
  }

  printf("%*s %s ::= %s ",indent,"",value->field->name,str);

  if(value->field->value_type!=CHOICE){
  printf("[");

  if(value->field->value_type==ANY && value->tlv){
    const char *type_str=type_t_toString(value->tlv->tlv.tag.type);
    const char *class_str=class_t_toString(value->tlv->tlv.tag.class);
    const char *tag_number_str=tag_number_t_toString(value->tlv->tlv.tag.number);
    printf("%s ",tag_number_str);
  }

  if(value->tlv==NULL) {
    printf("omitted");
  }else if (value->tlv->count <= 0 && value->field->value_type!=CHOICE) {
    for(int i=0; i<value->tlv->tlv.len; i++) {
      printf("%02X,",*(value->tlv->tlv.value+i));
    }
  } else if(value->field->value_type!=CHOICE && value->field->pc!=CONSTRUCTED && value->tlv && value->tlv->count>0){
    tlv_node_t *node=value->tlv->children[0];
    for(int i=0; i<node->tlv.len; i++) {
      printf("%02X,",*(node->tlv.value+i));
    }
    //print_node_values(value->tlv,0);
  }
  else {
    for(int i=value->tlv->tlv.len_meta+2; i>0; i--) {
      printf("%02X,",*(value->tlv->tlv.value-i));
    }
  }
  printf("]");
  }

  if(value->field->count > 0){
    printf("{");
  }
  printf("\n");
  for(int i=0; i<value->count; i++){
    print_field_value(value->children[i],indent+2);
  }
  if(value->field->count > 0){
    printf("%*s }\n",indent,"");
  }
}

bool validate_schema(field_t *field,tlv_node_t *tlv,field_value_t **out)
{
  if(field->required && tlv==NULL)
    return false;
  else if(field->required==false && tlv==NULL)
    return true;

  if(field->value_type==REFERENCE_TYPE){
    field_t *f=field->children[0];
    //TODO:this is a workaround, find a propery model 
    if(field->encoding_type!=NONE) {
      f->parent=field;
      f->encoding_type=field->encoding_type;
      f->tag_number=field->tag_number;
    }
    return validate_schema(f,tlv,out);
  }else if(field->value_type==CHOICE){
    field_value_t *parent_value=create_field_value(field,tlv);
    if(*out==NULL){
      *out=parent_value;
    }else {
      add_field_value(*out,parent_value);
    }
    for (int i=0; i<field->count; i++) {
      field_t *option_field=field->children[i];
      if (validate_schema(option_field,tlv,&parent_value)) {
        create_add_field_value(parent_value,option_field,tlv);
        return true;
      }
    }
    return false;
  }else if(field->value_type==ANY){
    return true;
  }else {
    tag_t t=tlv->tlv.tag;
    if(field->pc==PRIMITIVE){
      if(field->encoding_type==EXPLICIT) {

        if(tlv->count<=0) 
          return false;
        tlv_node_t *child=tlv->children[0];
        if(child->tlv.tag.number!=field->value_type)
          return false;
        if(field->tag_number!=t.number)
          return false;
        if (field->tag_class!=t.class)
          return false;

      }else if(field->encoding_type==IMPLICIT) {
        if(tlv->count>0)
          return false;
        if(field->tag_number!=t.number)
          return false;
      }else {
        if(field->value_type!=t.number)
          return false;
        if (field->tag_class!=t.class)
          return false;
        if (t.type!=PRIMITIVE)
          return false;
      }
    }else if(field->pc==CONSTRUCTED) {
      //validate outer tag of constructed types
      if (field->encoding_type==IMPLICIT){
        if(field->tag_number!=t.number)
          return false;
      }else if (field->encoding_type==EXPLICIT){
        if(tlv->count<=0) 
          return false;
        if(field->tag_number!=tlv->tlv.tag.number)
          return false;
        tlv=tlv->children[0];
      }else{
        if(field->value_type!=tlv->tlv.tag.number)
          return false;
      }
      field_value_t *parent_value=create_field_value(field,tlv);
      if(*out==NULL){
        *out=parent_value;
      }else {
        add_field_value(*out,parent_value);
      }
      if(field->value_type==SEQUENCE) {
        //SEQUENCE OF
        if(field->element_type!=0){
          if(tlv->count<=0)
            return false;
          if(field->value_type!=tlv->tlv.tag.number)
            return false;
          field_t *item_field=field->children[0];
          for (int i=0; i<tlv->count; i++) {
            tlv_node_t *item=tlv->children[i];
            if (validate_schema(item_field,item,&parent_value)==false)
              return false;
            else {
              //create_add_field_value(parent_value,item_field,&item);
            }
          }
          //return true;
        }
        //SEQUENCE
        else {
          int tlv_index=0;
          for (int i=0; i<field->count; i++) {
            field_t *f=field->children[i];
            tlv_node_t* tn=NULL;
            if(tlv->count>0 && tlv_index<tlv->count)
              tn=tlv->children[tlv_index];
            int required_count=0;
            for (int j=i; j<field->count; j++) {
              if (field->children[j]->required)
                required_count++;
            }
            int values_left=tlv->count-tlv_index;
            bool matches=validate_schema(f,tn,&parent_value);
            //required field and has no default value
            if (f->required && f->has_default==false) {
              if (matches==false)
                return false;
              else {
                tlv_index++;
                create_add_field_value(parent_value,f,tn);
              }
            }else {
              //optional field or has default value
              if(matches==false) {
                create_add_field_value(parent_value,f,NULL);
                continue;
              }else {
                if(values_left<=required_count) {
                  create_add_field_value(parent_value,f,NULL);
                  continue;
                }
                else {
                  tlv_index++;
                  create_add_field_value(parent_value,f,tn);
                }
              }
            }
          }
          if (tlv_index < tlv->count)
            return false;
        }
      }
      //TODO:validate order of elements in later stage
      else if(field->value_type==SET) {
        //SET OF
        if(field->element_type!=0){
          if(field->required && tlv->count<=0)
            return false;
          if(field->value_type!=tlv->tlv.tag.number)
            return false;
          field_t *item_field=field->children[0];
          for (int i=0; i<tlv->count; i++) {
            tlv_node_t *item=tlv->children[i];
            if (validate_schema(item_field,item,&parent_value)==false)
              return false;
            else {
              //create_add_field_value(parent_value,item_field,&item);
            }
          }
          //return true;
        }
      }
    }
  }

  return true;
}

/*
Certificate ::= SEQUENCE {
  tbsCertificate       TBSCertificate,
  signatureAlgorithm   AlgorithmIdentifier,
  signatureValue       BIT STRING
}

TBSCertificate ::= SEQUENCE {
  version         [0]  EXPLICIT INTEGER DEFAULT 0,
  serialNumber         INTEGER,
  signature            AlgorithmIdentifier,
  issuer               Name,
  validity             Validity,
  subject              Name,
  subjectPublicKeyInfo SubjectPublicKeyInfo
}

AlgorithmIdentifier ::= SEQUENCE {
  algorithm   OBJECT IDENTIFIER,
  parameters  ANY OPTIONAL
}

Name ::= SEQUENCE OF RelativeDistinguishedName

RelativeDistinguishedName ::= SET OF AttributeTypeAndValue

AttributeTypeAndValue ::= SEQUENCE {
  type   OBJECT IDENTIFIER,
  value  ANY
}

Validity ::= SEQUENCE {
  notBefore  Time,
  notAfter   Time
}

Time ::= CHOICE {
  utcTime      UTCTime,
  generalTime  GeneralizedTime
}

SubjectPublicKeyInfo ::= SEQUENCE {
  algorithm         AlgorithmIdentifier,
  subjectPublicKey  BIT STRING
}
 */
field_t* create_x509_definition()
{
  field_t *algorithm_identifier =create_field();
  algorithm_identifier->name = "AlgorithmIdentifier";
  algorithm_identifier->value_type = SEQUENCE;
  algorithm_identifier->pc = CONSTRUCTED;
  algorithm_identifier->required = true;

  field_t *ai_algorithm =create_field();
  ai_algorithm->name = "algorithm";
  ai_algorithm->value_type = OBJECT_IDENTIFIER;
  ai_algorithm->required = true;

  field_t *ai_parameters =create_field();
  ai_parameters->name = "parameters";
  ai_parameters->value_type = ANY;
  ai_parameters->required = false;

  add_field(algorithm_identifier, ai_algorithm);
  add_field(algorithm_identifier, ai_parameters);


  //AttributeTypeAndValue
  field_t *atv =create_field();
  atv->name = "AttributeTypeAndValue";
  atv->value_type = SEQUENCE;
  atv->pc = CONSTRUCTED;
  atv->required = true;

  field_t *atv_type =create_field();
  atv_type->name = "type";
  atv_type->value_type = OBJECT_IDENTIFIER;
  atv_type->required = true;

  field_t *atv_value =create_field();
  atv_value->name = "value";
  atv_value->value_type = ANY;
  atv_value->required = true;

  add_field(atv, atv_type);
  add_field(atv, atv_value);

  //RelativeDistinguishedName
  field_t *rdn =create_field();
  rdn->name = "RelativeDistinguishedName";
  rdn->value_type = SET;
  rdn->pc = CONSTRUCTED;
  rdn->element_type = REFERENCE_TYPE;
  rdn->reference_type = "AttributeTypeAndValue";
  rdn->required = true;

  add_field(rdn, atv);

  //Name
  field_t *name =create_field();
  name->name = "Name";
  name->value_type = SEQUENCE;
  name->pc = CONSTRUCTED;
  name->element_type = REFERENCE_TYPE;
  name->reference_type = "RelativeDistinguishedName";
  name->required = true;

  add_field(name, rdn);

  //Time
  field_t *time =create_field();
  time->name = "Time";
  time->value_type = CHOICE;
  time->required = true;

  field_t *utc_time =create_field();
  utc_time->name = "utcTime";
  utc_time->value_type = UTCTime;
  utc_time->required = true;

  field_t *gen_time =create_field();
  gen_time->name = "generalTime";
  gen_time->value_type = GeneralizedTime;
  gen_time->required = true;

  add_field(time, utc_time);
  add_field(time, gen_time);

  //Validity
  field_t *validity =create_field();
  validity->name = "Validity";
  validity->value_type = SEQUENCE;
  validity->pc = CONSTRUCTED;
  validity->required = true;

  field_t *not_before =create_field();
  not_before->name = "notBefore";
  not_before->value_type = REFERENCE_TYPE;
  not_before->reference_type = "Time";
  not_before->required = true;

  field_t *not_after =create_field();
  not_after->name = "notAfter";
  not_after->value_type = REFERENCE_TYPE;
  not_after->reference_type = "Time";
  not_after->required = true;

  add_field(validity, not_before);
  add_field(validity, not_after);

  add_field(not_before, time);
  add_field(not_after, time);

  //SubjectPublicKeyInfo
  field_t *spki =create_field();
  spki->name = "SubjectPublicKeyInfo";
  spki->value_type = SEQUENCE;
  spki->pc = CONSTRUCTED;
  spki->required = true;

  field_t *spki_alg =create_field();
  spki_alg->name = "algorithm";
  spki_alg->value_type = REFERENCE_TYPE;
  spki_alg->reference_type = "AlgorithmIdentifier";
  spki_alg->required = true;

  field_t *spki_key =create_field();
  spki_key->name = "subjectPublicKey";
  spki_key->value_type = BIT_STRING;
  spki_key->required = true;

  add_field(spki, spki_alg);
  add_field(spki, spki_key);

  add_field(spki_alg, algorithm_identifier);

  //TBSCertificate
  field_t *tbs =create_field();
  tbs->name = "TBSCertificate";
  tbs->value_type = SEQUENCE;
  tbs->pc = CONSTRUCTED;
  tbs->required = true;

  field_t *tbs_version =create_field();
  tbs_version->name = "version";
  tbs_version->tag_class = CONTEXT_SPECIFIC;
  tbs_version->tag_number = 0;
  tbs_version->encoding_type = EXPLICIT;
  tbs_version->value_type = INTEGER;
  tbs_version->required = false;
  tbs_version->has_default = true;

  field_t *tbs_serial =create_field();
  tbs_serial->name = "serialNumber";
  tbs_serial->value_type = INTEGER;
  tbs_serial->required = true;

  field_t *tbs_sig =create_field();
  tbs_sig->name = "signature";
  tbs_sig->value_type = REFERENCE_TYPE;
  tbs_sig->reference_type = "AlgorithmIdentifier";
  tbs_sig->required = true;

  field_t *tbs_issuer =create_field();
  tbs_issuer->name = "issuer";
  tbs_issuer->value_type = REFERENCE_TYPE;
  tbs_issuer->reference_type = "Name";
  tbs_issuer->required = true;

  field_t *tbs_validity =create_field();
  tbs_validity->name = "validity";
  tbs_validity->value_type = REFERENCE_TYPE;
  tbs_validity->reference_type = "Validity";
  tbs_validity->required = true;

  field_t *tbs_subject =create_field();
  tbs_subject->name = "subject";
  tbs_subject->value_type = REFERENCE_TYPE;
  tbs_subject->reference_type = "Name";
  tbs_subject->required = true;

  field_t *tbs_spki =create_field();
  tbs_spki->name = "subjectPublicKeyInfo";
  tbs_spki->value_type = REFERENCE_TYPE;
  tbs_spki->reference_type = "SubjectPublicKeyInfo";
  tbs_spki->required = true;

  field_t *tbs_extensions = create_field();
  tbs_extensions->name = "extensions";
  tbs_extensions->tag_class = CONTEXT_SPECIFIC;
  tbs_extensions->tag_number = 3;
  tbs_extensions->encoding_type = EXPLICIT;
  tbs_extensions->value_type = ANY;
  tbs_extensions->required = false;

  add_field(tbs, tbs_version);
  add_field(tbs, tbs_serial);
  add_field(tbs, tbs_sig);
  add_field(tbs, tbs_issuer);
  add_field(tbs, tbs_validity);
  add_field(tbs, tbs_subject);
  add_field(tbs, tbs_spki);
  add_field(tbs, tbs_extensions);

  add_field(tbs_sig, algorithm_identifier);
  add_field(tbs_issuer, name);
  add_field(tbs_validity, validity);
  add_field(tbs_subject, name);
  add_field(tbs_spki, spki);

  //Certificate
  field_t *certificate =create_field();
  certificate->name = "Certificate";
  certificate->value_type = SEQUENCE;
  certificate->pc = CONSTRUCTED;
  certificate->required = true;

  field_t *cert_tbs =create_field();
  cert_tbs->name = "tbsCertificate";
  cert_tbs->value_type = REFERENCE_TYPE;
  cert_tbs->reference_type = "TBSCertificate";
  cert_tbs->required = true;

  field_t *cert_alg =create_field();
  cert_alg->name = "signatureAlgorithm";
  cert_alg->value_type = REFERENCE_TYPE;
  cert_alg->reference_type = "AlgorithmIdentifier";
  cert_alg->required = true;

  field_t *cert_sig =create_field();
  cert_sig->name = "signatureValue";
  cert_sig->value_type = BIT_STRING;
  cert_sig->required = true;

  add_field(certificate, cert_tbs);
  add_field(certificate, cert_alg);
  add_field(certificate, cert_sig);

  add_field(cert_tbs, tbs);
  add_field(cert_alg, algorithm_identifier);
  return certificate;
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

