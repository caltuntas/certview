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
  printf("[");

  if(value->field->value_type==ANY && value->tlv){
    const char *type_str=type_t_toString(value->tlv->tlv.tag.type);
    const char *class_str=class_t_toString(value->tlv->tlv.tag.class);
    const char *tag_number_str=tag_number_t_toString(value->tlv->tlv.tag.number);
    printf("%s ",tag_number_str);
  }

  if(value->tlv==NULL) {
    printf("omitted");
  }else if (value->tlv->count <= 0) {
    for(int i=0; i<value->tlv->tlv.len; i++) {
      printf("%02X,",*(value->tlv->tlv.value+i));
    }
  } else if(value->tlv && value->tlv->count>0){
    tlv_node_t node=value->tlv->children[0];
    for(int i=0; i<node.tlv.len; i++) {
      printf("%02X,",*(node.tlv.value+i));
    }
    //print_node_values(value->tlv,0);
  }
  else {
    for(int i=value->tlv->tlv.len_meta+2; i>0; i--) {
      printf("%02X,",*(value->tlv->tlv.value-i));
    }
  }
  printf("]");

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
      if (validate_schema(option_field,tlv,out)) {
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
            tlv_node_t item=tlv->children[i];
            if (validate_schema(item_field,&item,out)==false)
              return false;
          }
          return true;
        }
        //SEQUENCE
        else {
          int tlv_index=0;
          for (int i=0; i<field->count; i++) {
            field_t *f=field->children[i];
            tlv_node_t* tn=NULL;
            if(tlv->count>0 && tlv_index<tlv->count)
              tn=&tlv->children[tlv_index];
            int required_count=0;
            for (int j=i; j<field->count; j++) {
              if (field->children[j]->required)
                required_count++;
            }
            int values_left=tlv->count-tlv_index;
            bool matches=validate_schema(f,tn,out);
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
            tlv_node_t item=tlv->children[i];
            if (validate_schema(item_field,&item,out)==false)
              return false;
          }
          return true;
        }
      }
    }
  }

  return true;
}

