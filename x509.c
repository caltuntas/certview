#include <stdio.h>
#include <stdlib.h>
#include "x509.h"

void add_field(field_t *parent, field_t *child)
{
	size_t cnt=parent->count;
	parent->children=realloc(parent->children,sizeof(field_t)*(parent->count+1));
	parent->children[cnt].name=child->name;
	parent->children[cnt].tag_number=child->tag_number;
	parent->children[cnt].tag_class=child->tag_class;
	parent->children[cnt].required=child->required;
	parent->children[cnt].match_type=child->match_type;
	parent->children[cnt].encoding_type=child->encoding_type;
	parent->children[cnt].value_type=child->value_type;
	parent->children[cnt].has_default=child->has_default;
	parent->count+=1;
}

static bool match(field_t f,tlv_node_t node)
{
  tag_t t=node.tlv.tag;
  if(f.encoding_type==EXPLICIT) {
    if(node.count<=0 || node.children[0].tlv.tag.number!=f.value_type) {
      return false;
    }
  }
  if(f.match_type==TAG) {
    if(f.tag_number!=t.number)
      return false;
  }
  if (f.tag_class!=t.class)
    return false;
  if (f.encoding_type!=EXPLICIT && f.value_type!=t.number)
    return false;
  return true;
}

bool validate_asn1(field_t *parent,tlv_node_t *tlv)
{
  if (tlv->count > parent->count)
    return false;
  int tlvIndex=0;
	for (int i=0; i<parent->count; i++) {
		field_t f=parent->children[i];
    tag_t tag=tlv->children[i].tlv.tag;
		if (f.match_type==POSITION) {
			if(f.required) {
				if(tag.number!=f.value_type)
					return false;
			}
		} else if(f.match_type==TAG) {
      bool matches=match(f,tlv->children[i]);
      if(matches==false) {
        if(tlv->count==parent->count)
          return false;
        if(f.has_default || !f.required) {
          tlvIndex++;
        }else {
          return false;
        }
      }
    }
	}
	return true;
}

