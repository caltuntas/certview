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

bool validate_schema(field_t *field,tlv_node_t *tlv)
{
  if(field->required && tlv==NULL)
    return false;
  else if(field->required==false && tlv==NULL)
    return true;

  if(field->value_type==REFERENCE_TYPE){
    field_t *f=field->children[0];
    //TODO:this is a workaround, find a propery model 
    if(field->encoding_type!=NONE) {
      f->encoding_type=field->encoding_type;
      f->tag_number=field->tag_number;
    }
    return validate_schema(f,tlv);
  }else if(field->value_type==CHOICE){
    for (int i=0; i<field->count; i++) {
      field_t *option_field=field->children[i];
      if (validate_schema(option_field,tlv))
        return true;
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
        tlv_node_t child=tlv->children[0];
        if(child.tlv.tag.number!=field->value_type)
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
        tlv=&tlv->children[0];
      }else{
        if(field->value_type!=tlv->tlv.tag.number)
          return false;
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
            tlv_node_t item=tlv->children[i];
            if (validate_schema(item_field,&item)==false)
              return false;
          }
          return true;
        }
        //SEQUENCE
        else {
          int tlv_index=0;
          for (int i=0; i<field->count; i++) {
            field_t *f=field->children[i];
            encoding_type_t e=f->encoding_type;
            tlv_node_t* tn=NULL;
            if(tlv->count>0 && tlv_index<tlv->count)
              tn=&tlv->children[tlv_index];
            int required_count=0;
            for (int j=i; j<field->count; j++) {
              if (field->children[j]->required)
                required_count++;
            }
            int values_left=tlv->count-tlv_index;
            bool matches=validate_schema(f,tn);
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
            tlv_node_t item=tlv->children[i];
            if (validate_schema(item_field,&item)==false)
              return false;
          }
          return true;
        }
      }
    }
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
      if (validate_schema(option_field,tlv)){
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
      if (validate_schema(item_field,&item)==false)
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
      if (validate_schema(item_field,&item)==false)
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
      matches=validate_schema(f,tn);
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
