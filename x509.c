#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "x509.h"
#include "bigint.h"
#include "oid.h"

bit_string_t *bit_string_create(uint8_t *buf,size_t len)
{
  bit_string_t *bitstr=malloc(sizeof(*bitstr));
  bitstr->data=calloc(len,sizeof(uint8_t));
  memcpy(bitstr->data,buf,len);
  bitstr->length=len;
  bitstr->unused_bits=buf[0];
  bitstr->bit_length=8*sizeof(uint8_t)*(len-1)-bitstr->unused_bits;
  return bitstr;
}

octet_string_t *octet_string_create(uint8_t *buf,size_t len)
{
  octet_string_t *os=malloc(sizeof(*os));
  os->data=calloc(len,sizeof(uint8_t));
  memcpy(os->data,buf,len);
  os->length=len;
  return os;
}

ia5_string_t *ia5_string_create(uint8_t *buf,size_t len)
{
  ia5_string_t *ia5=malloc(sizeof(*ia5));
  ia5->data=calloc(len,sizeof(uint8_t));
  memcpy(ia5->data,buf,len);
  ia5->length=len;
  return ia5;
}

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
  child->parent=parent;
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

field_t *field_find_child_by_name(field_t *parent,char *child_name)
{
  for(int i=0; i<parent->count; i++){
    field_t *child=parent->children[i];
    if(strcmp(child->name,child_name)==0)
      return child;
  }
  return NULL;
}

field_t* create_field()
{
  field_t *f=calloc(1,sizeof(field_t));
  return f;
}

//TODO:while recursively validating and mapping fields, this function is called multiple time
//but who should call it is inconsistent, private types or constructed types , ownership check
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
  char str[100]={0};
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
    if(value->decoded) {
      if(value->field->value_type==OBJECT_IDENTIFIER){
        char *str=oid_to_str(value->value.oid);
        printf(" - %s",str);
      }
      if(value->field->value_type==BIT_STRING){
        char *str=bit_string_to_str(value->value.bitstring);
        printf(" - %s",str);
      }
      if(value->field->value_type==INTEGER && value->value.bigint!=NULL){
        char *str=bigint_to_decimal_str(value->value.bigint);
        printf(" - %s",str);
      }
      if(value->field->value_type==OCTET_STRING){
        char *str=octet_string_to_str(value->value.octetstring);
        printf(" - %s",str);
      }
      if(value->field->value_type==IA5String){
        char *str=ia5_string_to_str(value->value.ia5string);
        printf(" - %s",str);
      }
    }
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
field_value_t *set_or_add_field_value(field_t *field,tlv_node_t *tlv,field_value_t **out)
{
  field_value_t *parent_value=create_field_value(field,tlv);
  if(*out==NULL){
    *out=parent_value;
  }else {
    if(parent_value->field->element_type==0)
      add_field_value(*out,parent_value);
  }
  return parent_value;
}

//TODO:handle primitive type mapping, example standalone integer,string etc.
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
    field_value_t *parent_value=set_or_add_field_value(field,tlv,out);
    for (int i=0; i<field->count; i++) {
      field_t *option_field=field->children[i];
      if (validate_schema(option_field,tlv,&parent_value)) {
        create_add_field_value(parent_value,option_field,tlv);
        return true;
      }
    }
    return false;
  }else if(field->value_type==ANY){
    //TODO:duplicated implicit and explicit checks are everywhere
    if(field->encoding_type==IMPLICIT || field->encoding_type==EXPLICIT) {
      if(field->tag_number!=tlv->tlv.tag.number)
        return false;
    }
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
      field_value_t *parent_value=set_or_add_field_value(field,tlv,out);
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
            if (validate_schema(item_field,item,&parent_value)==false){
              return false;
            } else {
              //create_add_field_value(parent_value,item_field,item);
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
              //optional field or has default value but current tlv does not match
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
      //TODO:missing mapping
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

  if(*out==NULL){
    field_value_t *parent_value=create_field_value(field,tlv);
    *out=parent_value;
  }
  return true;
}

field_t *x509_name_definition()
{
  //Name
  field_t *name =create_field();
  name->name = "Name";
  name->value_type = SEQUENCE;
  name->pc = CONSTRUCTED;
  name->element_type = REFERENCE_TYPE;
  name->reference_type = "RelativeDistinguishedName";
  name->required = true;

  //RelativeDistinguishedName
  field_t *rdn =create_field();
  rdn->name = "RelativeDistinguishedName";
  rdn->value_type = SET;
  rdn->pc = CONSTRUCTED;
  rdn->element_type = REFERENCE_TYPE;
  rdn->reference_type = "AttributeTypeAndValue";
  rdn->required = true;

  add_field(name, rdn);

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
  add_field(rdn, atv);

  return name;
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
  extensions      [3]  EXPLICIT Extensions OPTIONAL
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

Extensions ::= SEQUENCE OF Extension

Extension ::= SEQUENCE {
  extnID     OBJECT IDENTIFIER,
  critical   BOOLEAN OPTIONAL,
  extnValue  OCTET STRING
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

  field_t *name =x509_name_definition();

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


  field_t *extension =create_field();
  extension->name = "Extension";
  extension->value_type = SEQUENCE;
  extension->pc = CONSTRUCTED;
  extension->required = true;

  field_t *extnID =create_field();
  extnID->name = "extnID";
  extnID->value_type = OBJECT_IDENTIFIER;
  extnID->required = true;

  field_t *critical =create_field();
  critical->name = "critical";
  critical->value_type = BOOLEAN;
  critical->required = false;
  critical->has_default = true;   // DEFAULT FALSE

  field_t *extnValue =create_field();
  extnValue->name = "extnValue";
  extnValue->value_type = OCTET_STRING;
  extnValue->required = true;

  add_field(extension, extnID);
  add_field(extension, critical);
  add_field(extension, extnValue);


  field_t *extensions_seq =create_field();
  extensions_seq->name = "Extensions";
  extensions_seq->value_type = SEQUENCE;
  extensions_seq->pc = CONSTRUCTED;
  extensions_seq->element_type = REFERENCE_TYPE;
  extensions_seq->reference_type = "Extension";
  extensions_seq->required = true;

  add_field(extensions_seq, extension);

  field_t *tbs_extensions =create_field();
  tbs_extensions->name = "extensions";
  tbs_extensions->tag_class = CONTEXT_SPECIFIC;
  tbs_extensions->tag_number = 3;
  tbs_extensions->encoding_type = EXPLICIT;
  tbs_extensions->value_type = REFERENCE_TYPE;
  tbs_extensions->reference_type = "Extensions";
  tbs_extensions->required = false;

  add_field(tbs_extensions, extensions_seq);

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

//TODO:handle null tlv values
void decode(field_value_t *value,decoder_t *decoder)
{
  if(value->count<=0){
    if(value->field->value_type==INTEGER) {
      if(value->tlv!=NULL)
        value->value.bigint=create_bigint(value->tlv->tlv.value,value->tlv->tlv.len);      
      else
        value->value.bigint=NULL;      
      value->decoded=true;
    }
    if(value->field->value_type==OBJECT_IDENTIFIER) {
      value->value.oid=oid_create(value->tlv->tlv.value,value->tlv->tlv.len);
      value->decoded=true;
    }
    if(value->field->value_type==BIT_STRING) {
      value->value.bitstring=bit_string_create(value->tlv->tlv.value,value->tlv->tlv.len);
      value->decoded=true;
    }
    if(value->field->value_type==IA5String) {
      value->value.ia5string=ia5_string_create(value->tlv->tlv.value,value->tlv->tlv.len);
      value->decoded=true;
    }
    if(value->field->value_type==OCTET_STRING) {
      if(decoder!=NULL) {
        decoder->decoder_func(value);
      } else {
        value->value.octetstring=octet_string_create(value->tlv->tlv.value,value->tlv->tlv.len);
        value->decoded=true;
      }
    }
  }

  for(int i=0; i<value->count; i++){
    field_value_t *child_val=value->children[i];
    decode(child_val,decoder);
  }
}

char *byte_to_binary_str(uint8_t byte,size_t unused_bits)
{
  char *bits=malloc(8*sizeof(char));
  return bits;
}

char *bit_string_to_str(bit_string_t *bitstring)
{
  char *bits=calloc(bitstring->bit_length+1,sizeof(char));
  for(int i=1; i<bitstring->length; i++){
    uint8_t byte=bitstring->data[i];
    int bit_count=8;
    if(i==bitstring->length-1)
      bit_count=bit_count-bitstring->unused_bits;
    int shift_counter=7;
    for (int j=0;j<bit_count; j++) {
      int index=j+((i-1)*8);
      bits[index]='0'+((byte >> (shift_counter-j)) & 1);
    }
  }
  return bits;
}

char *octet_string_to_str(octet_string_t *octetstring)
{
  char *str=calloc(octetstring->length+1,sizeof(char));
  sprintf(str,"%s",octetstring->data);
  return str;
}

char *ia5_string_to_str(ia5_string_t *ia5string)
{
  char *str=calloc(ia5string->length+1,sizeof(char));
  sprintf(str,"%s",ia5string->data);
  return str;
}

/*
id-ce-subjectAltName OBJECT IDENTIFIER ::= { id-ce 17 }

SubjectAltName ::= GeneralNames

GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

GeneralName ::= CHOICE {
    otherName                       [0]  AnotherName,
    rfc822Name                      [1]  IA5String,
    dNSName                         [2]  IA5String,
    x400Address                     [3]  ORAddress,
    directoryName                   [4]  Name,
    ediPartyName                    [5]  EDIPartyName,
    uniformResourceIdentifier       [6]  IA5String,
    iPAddress                       [7]  OCTET STRING,
    registeredID                    [8]  OBJECT IDENTIFIER
}
*/


/*
id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

KeyPurposeId ::= OBJECT IDENTIFIER
 */

field_t *x509_extensions_extended_key_usage_definition()
{
  field_t *key_usage =create_field();
  key_usage->name = "ExtKeyUsageSyntax";
  key_usage->value_type = SEQUENCE;
  key_usage->pc = CONSTRUCTED;
  key_usage->element_type = REFERENCE_TYPE;
  key_usage->reference_type = "KeyPurposeId";
  key_usage->required = true;

  field_t *purpose =create_field();
  purpose->name = "KeyPurposeId";
  purpose->value_type = OBJECT_IDENTIFIER;
  purpose->pc = PRIMITIVE;
  purpose->required = true;

  add_field(key_usage, purpose);
  return key_usage;
}

/*
id-ce-keyUsage OBJECT IDENTIFIER ::= { id-ce 15 }
KeyUsage ::= BIT STRING {
    digitalSignature        (0),
    nonRepudiation          (1),
    keyEncipherment         (2),
    dataEncipherment        (3),
    keyAgreement            (4),
    keyCertSign             (5),
    cRLSign                 (6),
    encipherOnly            (7),
    decipherOnly            (8)
}
*/
field_t *x509_extensions_key_usage_definition()
{
  field_t *key_usage =create_field();
  key_usage->name = "KeyUsage";
  key_usage->value_type = BIT_STRING;
  key_usage->required = true;
  return key_usage;
}

/*
-- OID: 2.5.29.19
BasicConstraints ::= SEQUENCE {
     cA                      BOOLEAN DEFAULT FALSE,
     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
}
*/
field_t *x509_extensions_basic_constraints_definition()
{
  field_t *field_basic_constraints =create_field();
  field_basic_constraints->name = "BasicConstraints";
  field_basic_constraints->value_type = SEQUENCE;
  field_basic_constraints->pc = CONSTRUCTED;
  field_basic_constraints->required = true;

  field_t *field_ca =create_field();
  field_ca->name = "cA";
  field_ca->value_type = BOOLEAN;
  field_ca->has_default = true;

  field_t *field_path_len =create_field();
  field_path_len->name = "pathLenConstraint";
  field_path_len->value_type = INTEGER;
  field_path_len->required = false;

  add_field(field_basic_constraints, field_ca);
  add_field(field_basic_constraints, field_path_len);

  return field_basic_constraints;
}

/*
AnotherName ::= SEQUENCE {
     type-id    OBJECT IDENTIFIER,
     value      [0] EXPLICIT ANY DEFINED BY type-id
}
EDIPartyName ::= SEQUENCE {
     nameAssigner            [0] DirectoryString OPTIONAL,
     partyName               [1] DirectoryString
}
GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

GeneralName ::= CHOICE {
     otherName                       [0]     AnotherName,
     rfc822Name                      [1]     IA5String,
     dNSName                         [2]     IA5String,
     x400Address                     [3]     ORAddress,
     directoryName                   [4]     Name,
     ediPartyName                    [5]     EDIPartyName,
     uniformResourceIdentifier       [6]     IA5String,
     iPAddress                       [7]     OCTET STRING,
     registeredID                    [8]     OBJECT IDENTIFIER
}
*/
field_t *x509_general_names_definition()
{
  field_t *another_name = create_field();
  another_name->name = "AnotherName";
  another_name->value_type = SEQUENCE;
  another_name->pc = CONSTRUCTED;
  another_name->required = true;

  field_t *an_type_id = create_field();
  an_type_id->name = "type-id";
  an_type_id->value_type = OBJECT_IDENTIFIER;
  an_type_id->required = true;

  field_t *an_value = create_field();
  an_value->name = "value";
  an_value->tag_class = CONTEXT_SPECIFIC;
  an_value->tag_number = 0;
  an_value->encoding_type = EXPLICIT;
  an_value->value_type = ANY;
  an_value->required = true;

  add_field(another_name, an_type_id);
  add_field(another_name, an_value);

  field_t *edi_party_name = create_field();
  edi_party_name->name = "EDIPartyName";
  edi_party_name->value_type = SEQUENCE;
  edi_party_name->pc = CONSTRUCTED;
  edi_party_name->required = true;

  field_t *edi_name_assigner = create_field();
  edi_name_assigner->name = "nameAssigner";
  edi_name_assigner->tag_class = CONTEXT_SPECIFIC;
  edi_name_assigner->tag_number = 0;
  edi_name_assigner->value_type = ANY;   // DirectoryString
  edi_name_assigner->required = false;

  field_t *edi_party = create_field();
  edi_party->name = "partyName";
  edi_party->tag_class = CONTEXT_SPECIFIC;
  edi_party->tag_number = 1;
  edi_party->value_type = ANY;   // DirectoryString
  edi_party->required = true;

  add_field(edi_party_name, edi_name_assigner);
  add_field(edi_party_name, edi_party);

  field_t *general_name = create_field();
  general_name->name = "GeneralName";
  general_name->value_type = CHOICE;
  general_name->required = true;

  field_t *gn_other = create_field();
  gn_other->name = "otherName";
  gn_other->tag_class = CONTEXT_SPECIFIC;
  gn_other->tag_number = 0;
  gn_other->encoding_type = IMPLICIT;
  gn_other->value_type = REFERENCE_TYPE;
  gn_other->reference_type = "AnotherName";
  gn_other->required = true;

  add_field(gn_other, another_name);

  field_t *gn_rfc822 = create_field();
  gn_rfc822->name = "rfc822Name";
  gn_rfc822->tag_class = CONTEXT_SPECIFIC;
  gn_rfc822->tag_number = 1;
  gn_rfc822->encoding_type = IMPLICIT;
  gn_rfc822->value_type = IA5String;
  gn_rfc822->required = true;

  field_t *gn_dns = create_field();
  gn_dns->name = "dNSName";
  gn_dns->tag_class = CONTEXT_SPECIFIC;
  gn_dns->tag_number = 2;
  gn_dns->encoding_type = IMPLICIT;
  gn_dns->value_type = IA5String;
  gn_dns->required = true;

  field_t *gn_x400 = create_field();
  gn_x400->name = "x400Address";
  gn_x400->tag_class = CONTEXT_SPECIFIC;
  gn_x400->tag_number = 3;
  gn_x400->encoding_type = IMPLICIT;
  gn_x400->value_type = ANY;   // ORAddress
  gn_x400->required = true;

  field_t *gn_dir = create_field();
  gn_dir->name = "directoryName";
  gn_dir->tag_class = CONTEXT_SPECIFIC;
  gn_dir->tag_number = 4;
  gn_dir->value_type = REFERENCE_TYPE;
  gn_dir->encoding_type = IMPLICIT;
  gn_dir->reference_type = "Name";
  gn_dir->pc = CONSTRUCTED;
  gn_dir->required = true;

  field_t *name =x509_name_definition();

  add_field(gn_dir,name);


  field_t *gn_edi = create_field();
  gn_edi->name = "ediPartyName";
  gn_edi->tag_class = CONTEXT_SPECIFIC;
  gn_edi->tag_number = 5;
  gn_edi->value_type = REFERENCE_TYPE;
  gn_edi->encoding_type = IMPLICIT;
  gn_edi->reference_type = "EDIPartyName";
  gn_edi->pc = CONSTRUCTED;
  gn_edi->required = true;

  add_field(gn_edi, edi_party_name);

  field_t *gn_uri = create_field();
  gn_uri->name = "uniformResourceIdentifier";
  gn_uri->tag_class = CONTEXT_SPECIFIC;
  gn_uri->tag_number = 6;
  gn_uri->encoding_type = IMPLICIT;
  gn_uri->value_type = IA5String;
  gn_uri->required = true;

  field_t *gn_ip = create_field();
  gn_ip->name = "iPAddress";
  gn_ip->tag_class = CONTEXT_SPECIFIC;
  gn_ip->tag_number = 7;
  gn_ip->encoding_type = IMPLICIT;
  gn_ip->value_type = OCTET_STRING;
  gn_ip->required = true;

  field_t *gn_regid = create_field();
  gn_regid->name = "registeredID";
  gn_regid->tag_class = CONTEXT_SPECIFIC;
  gn_regid->tag_number = 8;
  gn_regid->encoding_type = IMPLICIT;
  gn_regid->value_type = OBJECT_IDENTIFIER;
  gn_regid->required = true;

  add_field(general_name, gn_other);
  add_field(general_name, gn_rfc822);
  add_field(general_name, gn_dns);
  add_field(general_name, gn_x400);
  add_field(general_name, gn_dir);
  add_field(general_name, gn_edi);
  add_field(general_name, gn_uri);
  add_field(general_name, gn_ip);
  add_field(general_name, gn_regid);

  field_t *general_names = create_field();
  general_names->name = "GeneralNames";
  general_names->value_type = SEQUENCE;
  general_names->pc = CONSTRUCTED;
  general_names->element_type = REFERENCE_TYPE;
  general_names->reference_type = "GeneralName";
  general_names->required = true;

  add_field(general_names, general_name);

  return general_names;
}

/*
id-ce-subjectAltName OBJECT IDENTIFIER ::= { id-ce 17 }

SubjectAltName ::= GeneralNames
 */
field_t *x509_san_definition()
{
  field_t *san = create_field();
  san->name = "SubjectAltName";
  san->value_type = REFERENCE_TYPE;
  san->pc = CONSTRUCTED;
  san->reference_type = "GeneralNames";
  san->required = true;

  field_t *general_names=x509_general_names_definition();

  add_field(san, general_names);

  return san;
}

/*
-- OID: 2.5.29.35
AuthorityKeyIdentifier ::= SEQUENCE {
     keyIdentifier             [0] KeyIdentifier            OPTIONAL,
     authorityCertIssuer       [1] GeneralNames             OPTIONAL,
     authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL
}
KeyIdentifier ::= OCTET STRING
*/
field_t *x509_extensions_key_identifier_definition()
{
  field_t *authority_key_identifier = create_field();
  authority_key_identifier->name = "AuthorityKeyIdentifier";
  authority_key_identifier->value_type = SEQUENCE;
  authority_key_identifier->pc = CONSTRUCTED;
  authority_key_identifier->required = true;

  field_t *aki_keyid = create_field();
  aki_keyid->name = "keyIdentifier";
  aki_keyid->tag_class = CONTEXT_SPECIFIC;
  aki_keyid->tag_number = 0;
  aki_keyid->encoding_type = IMPLICIT;
  aki_keyid->value_type = OCTET_STRING;
  aki_keyid->required = false;

  field_t *aki_issuer = create_field();
  aki_issuer->name = "authorityCertIssuer";
  aki_issuer->tag_class = CONTEXT_SPECIFIC;
  aki_issuer->tag_number = 1;
  aki_issuer->encoding_type = IMPLICIT;
  aki_issuer->value_type = REFERENCE_TYPE;
  aki_issuer->reference_type = "GeneralNames";
  aki_issuer->pc = CONSTRUCTED;
  aki_issuer->required = false;

  field_t *general_names=x509_general_names_definition();
  add_field(aki_issuer, general_names);

  field_t *aki_serial = create_field();
  aki_serial->name = "authorityCertSerialNumber";
  aki_serial->tag_class = CONTEXT_SPECIFIC;
  aki_serial->tag_number = 2;
  aki_serial->encoding_type = IMPLICIT;
  aki_serial->value_type = INTEGER;
  aki_serial->required = false;


  add_field(authority_key_identifier, aki_keyid);
  add_field(authority_key_identifier, aki_issuer);
  add_field(authority_key_identifier, aki_serial);

  return authority_key_identifier;
}

void decode_basic_constraints(field_value_t *fv)
{
  field_t *field_basic_constraints=x509_extensions_basic_constraints_definition();
  field_t *field_key_identifier=x509_extensions_key_identifier_definition();
  field_value_t *extnID=NULL;
  field_value_t *parent=fv->parent;
  for(int i=0; i<parent->count; i++){
    field_value_t *child_val=parent->children[i];
    field_t *child_field=child_val->field;
    if(strcmp(child_field->name,"extnID")==0){
      oid_t *oid=child_val->value.oid;
      char *oid_str =oid_to_str(oid);
      if(strcmp(oid_str,"2.5.29.19")==0) {
        field_value_t *out=NULL;
        tlv_t actual = parse_tlv(fv->tlv->tlv.value,fv->tlv->tlv.len);
        tlv_node_t *root = build_tlv(actual);
        bool is_valid=validate_schema(field_basic_constraints,root,&out);
        if(is_valid){
          add_field_value(fv,out);
        }
      }
      if(strcmp(oid_str,"2.5.29.35")==0) {
        field_value_t *out=NULL;
        tlv_t actual = parse_tlv(fv->tlv->tlv.value,fv->tlv->tlv.len);
        tlv_node_t *root = build_tlv(actual);
        bool is_valid=validate_schema(field_key_identifier,root,&out);
        print_debug(is_valid,fv->tlv->tlv.value,fv->tlv->tlv.len,root,field_key_identifier,out);
        if(is_valid){
          add_field_value(fv,out);
        }
      }
      if(strcmp(oid_str,"2.5.29.15")==0) {
        field_t *field_key_usage=x509_extensions_key_usage_definition();
        field_value_t *out=NULL;
        tlv_t actual = parse_tlv(fv->tlv->tlv.value,fv->tlv->tlv.len);
        tlv_node_t *root = build_tlv(actual);
        bool is_valid=validate_schema(field_key_usage,root,&out);
        print_debug(is_valid,fv->tlv->tlv.value,fv->tlv->tlv.len,root,field_key_usage,out);
        if(is_valid){
          add_field_value(fv,out);
        }
      }
      if(strcmp(oid_str,"2.5.29.37")==0) {
        field_t *field_ext_key_usage=x509_extensions_extended_key_usage_definition();
        field_value_t *out=NULL;
        tlv_t actual = parse_tlv(fv->tlv->tlv.value,fv->tlv->tlv.len);
        tlv_node_t *root = build_tlv(actual);
        bool is_valid=validate_schema(field_ext_key_usage,root,&out);
        print_debug(is_valid,fv->tlv->tlv.value,fv->tlv->tlv.len,root,field_ext_key_usage,out);
        if(is_valid){
          add_field_value(fv,out);
        }
      }
      if(strcmp(oid_str,"2.5.29.17")==0) {
        field_t *field_san=x509_san_definition();
        field_value_t *out=NULL;
        tlv_t actual = parse_tlv(fv->tlv->tlv.value,fv->tlv->tlv.len);
        tlv_node_t *root = build_tlv(actual);
        bool is_valid=validate_schema(field_san,root,&out);
        print_debug(is_valid,fv->tlv->tlv.value,fv->tlv->tlv.len,root,field_san,out);
        if(is_valid){
          add_field_value(fv,out);
        }
      }
    }
  }
}
