#include <stdio.h>
#include <stdlib.h>
#include "x509.h"


void add_field(field_t *parent, field_t *child)
{
	size_t cnt=parent->count;
	parent->children=realloc(parent->children,sizeof(field_t*)*(parent->count+1));
	parent->children[cnt]=child;
	parent->count+=1;
}

void print_field(field_t *field,int indent) 
{
  const char *tag_number_str=tag_number_t_toString(field->value_type);
  char str[40]={0};
  if(tag_number_str==NULL) {
    if(field->tag_class==CONTEXT_SPECIFIC && field->encoding_type==EXPLICIT){
      sprintf(str,"[%d] EXPLICIT",field->tag_number);
      tag_number_str=str;
    } else if(field->tag_class ==CONTEXT_SPECIFIC && field->encoding_type==IMPLICIT){
      sprintf(str,"[%d] IMPLICIT",field->tag_number);
      tag_number_str=str;
    }
    if(field->value_type==REFERENCE_TYPE) 
      sprintf(str,"%s",field->children[0]->name);
    else
      sprintf(str,"%s",field->name);
    tag_number_str=str;
  } 

  printf("%*s %s ::= %s ",indent,"",field->name,tag_number_str);
  if(field->count > 0){
    printf("{");
  }
    printf("\n");
  //if(field->value_type==REFERENCE_TYPE)
    //return;
  for(int i=0; i<field->count; i++){
    print_field(field->children[i],indent+1);
  }
}

bool validate_asn1(field_t *field,tlv_node_t *tlv)
{
  tag_t t=tlv->tlv.tag;
  if(field->value_type==ANY)
    return true;
  if(field->value_type==CHOICE) {
    for (int i=0; i<field->count; i++) {
      field_t *option_field=field->children[i];
      if (validate_asn1(option_field,tlv))
        return true;
    }
    return false;
  }
  if(field->encoding_type==EXPLICIT) {
    if(tlv->count<=0 || tlv->children[0].tlv.tag.number!=field->value_type) {
      return false;
    }
  }
  if(field->encoding_type==IMPLICIT){
    if(tlv->count>0)
      return false;
  }
  if(field->match_type==TAG) {
    if(field->tag_number!=t.number)
      return false;
  }
  if (field->tag_class!=t.class)
    return false;
  if ((field->encoding_type!=EXPLICIT && field->encoding_type!=IMPLICIT) && field->value_type!=t.number)
    return false;

  if(field->value_type==SEQUENCE && field->element_type!=0) {
    if(field->required && tlv->count<=0)
      return false;
    field_t *item_field=field->children[0];
    for (int i=0; i<tlv->count; i++) {
      tlv_node_t item=tlv->children[i];
      if (validate_asn1(item_field,&item)==false)
        return false;
    }
    return true;
  }

  if (field->value_type==SEQUENCE) {
    bool prev_match=true;
    int tlv_index=0;
    bool matches=false;
    for (int i=0; i<field->count; i++) {
      field_t *f=field->children[i];
      tlv_node_t* tn=NULL;
      if(tlv->count>0)
        tn=&tlv->children[tlv_index];
      else
        tn=tlv;
      if(f->value_type==REFERENCE_TYPE)
        f=f->children[0];
      matches=validate_asn1(f,tn);
      if(matches==false) {
        if(f->required)
          return false;
        else {
          if(prev_match==false)
            return false;
          if(f->has_default || f->required==false){
            prev_match=matches;
            continue;
          }
        }
      }
      tlv_index++;
      prev_match=matches;
    }
    if (tlv_index < tlv->count)
      return false;
  }
  return true;
}

