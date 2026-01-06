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

void add_field_value(field_value_t *parent, field_value_t *child)
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

  //TODO:validate order of elements in later stage
  if(field->value_type==SET && field->element_type!=0) {
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
      int required_count=0;
      for (int j=i; j<field->count; j++) {
        if (field->children[j]->required)
          required_count++;
      }
      int values_left=tlv->count-tlv_index;
      matches=validate_asn1(f,tn);
      //required field and has no default value
      if (f->required && f->has_default==false) {
        if (matches==false)
          return false;
        else
          tlv_index++;
      }else {
      //optional field or has default value
        if(matches==false) {
          continue;
        }else {
          if(values_left<=required_count)
            continue;
          else
            tlv_index++;
        }

      }
    }
    if (tlv_index < tlv->count)
      return false;
  }
  return true;
}

void bind_schema(field_t *field, tlv_node_t *tlv,field_value_t **out)
{
  *out=NULL;
  tag_t t=tlv->tlv.tag;
  if(field->value_type==ANY)
    return;
  if(field->value_type==CHOICE) {
    field_value_t *value=calloc(1,sizeof(field_value_t));
    value->field=field;
    value->tlv=NULL;
    *out=value;
    for (int i=0; i<field->count; i++) {
      field_t *option_field=field->children[i];
      if (validate_asn1(option_field,tlv)){
        field_value_t *child_value=calloc(1,sizeof(field_value_t));
        child_value->field=option_field;
        child_value->tlv=tlv;
        add_field_value(value,child_value);
        break;
      }
    }
    return;
  }
  if(field->encoding_type==EXPLICIT) {
    if(tlv->count<=0 || tlv->children[0].tlv.tag.number!=field->value_type) {
      return;
    }
  }
  if(field->encoding_type==IMPLICIT){
    if(tlv->count>0)
      return;
  }
  if(field->match_type==TAG) {
    if(field->tag_number!=t.number)
      return;
  }
  if (field->tag_class!=t.class)
    return;
  if ((field->encoding_type!=EXPLICIT && field->encoding_type!=IMPLICIT) && field->value_type!=t.number)
    return;

  if(field->value_type==SEQUENCE && field->element_type!=0) {
    if(field->required && tlv->count<=0)
      return;
    field_t *item_field=field->children[0];
    for (int i=0; i<tlv->count; i++) {
      tlv_node_t item=tlv->children[i];
      if (validate_asn1(item_field,&item)==false)
        return;
    }
    return;
  }

  //TODO:validate order of elements in later stage
  if(field->value_type==SET && field->element_type!=0) {
    if(field->required && tlv->count<=0)
      return;
    field_t *item_field=field->children[0];
    for (int i=0; i<tlv->count; i++) {
      tlv_node_t item=tlv->children[i];
      if (validate_asn1(item_field,&item)==false)
        return;
    }
    return;
  }

  if (field->value_type==SEQUENCE) {
    field_value_t *value=calloc(1,sizeof(field_value_t));
    value->field=field;
    value->tlv=tlv;
    *out=value;
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
      int required_count=0;
      for (int j=i; j<field->count; j++) {
        if (field->children[j]->required)
          required_count++;
      }
      int values_left=tlv->count-tlv_index;
      matches=validate_asn1(f,tn);
      //required field and has no default value
      if (f->required && f->has_default==false) {
        if (matches){
            field_value_t *child_value=calloc(1,sizeof(field_value_t));
            child_value->field=f;
            child_value->tlv=tn;
            add_field_value(value,child_value);
            tlv_index++;
        }
      }else {
      //optional field or has default value
        if(matches==false) {
          continue;
        }else {
          if(values_left<=required_count) {
            field_value_t *child_value=calloc(1,sizeof(field_value_t));
            child_value->field=f;
            child_value->tlv=NULL;
            add_field_value(value,child_value);
            continue;
          }
          else {
            field_value_t *child_value=calloc(1,sizeof(field_value_t));
            child_value->field=f;
            child_value->tlv=tn;
            add_field_value(value,child_value);
            tlv_index++;
          }
        }
      }
    }
    if (tlv_index < tlv->count)
      return;
  }
  return;

}
