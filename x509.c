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

static bool match(field_t *f,tlv_node_t node)
{
  tag_t t=node.tlv.tag;
  if(f->value_type==CHOICE) {
    for (int i=0; i<f->count; i++) {
      field_t *option_field=f->children[i];
      if (option_field->value_type==t.number)
        return true;
    }
    return false;
  }
  if(f->encoding_type==EXPLICIT) {
    if(node.count<=0 || node.children[0].tlv.tag.number!=f->value_type) {
      return false;
    }
  }
  if(f->encoding_type==IMPLICIT){
    if(node.count>0)
      return false;
  }
  if(f->match_type==TAG) {
    if(f->tag_number!=t.number)
      return false;
  }
  if (f->tag_class!=t.class)
    return false;
  if ((f->encoding_type!=EXPLICIT && f->encoding_type!=IMPLICIT) && f->value_type!=t.number)
    return false;
  return true;
}

bool validate_asn1(field_t *parent,tlv_node_t *tlv)
{
  if (tlv->count > parent->count)
    return false;
  int tlvIndex=0;
	for (int i=0; i<parent->count; i++) {
		field_t *f=parent->children[i];
    tag_t tag=tlv->children[i].tlv.tag;
		if (f->match_type==POSITION) {
      bool matches=match(f,tlv->children[i]);
			if(f->required && matches==false) {
					return false;
			}
		} else if(f->match_type==TAG) {
      bool matches=match(f,tlv->children[i]);
      if(matches==false) {
        if(tlv->count==parent->count)
          return false;
        if(f->has_default || !f->required) {
          tlvIndex++;
        }else {
          return false;
        }
      }
    }
	}
	return true;
}

