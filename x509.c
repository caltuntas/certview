#include <stdio.h>
#include <stdlib.h>
#include "x509.h"

void add_field(field_t *parent, field_t *child)
{
	size_t cnt=parent->count;
	parent->children=realloc(parent->children,sizeof(field_t)*(parent->count+1));
	parent->children[cnt].asn1_type=child->asn1_type;
	parent->children[cnt].required=child->required;
	parent->children[cnt].name=child->name;
	parent->count+=1;
}

bool validate_asn1(field_t *parent,tlv_node_t *tlv)
{
  if (tlv->count > parent->count)
    return false;
	for (int i=0; i<parent->count; i++) {
		field_t f=parent->children[i];
		if (f.match_type==POSITION) {
			if(f.required) {
				if(tlv->children[i].tlv.tag.number!=f.asn1_type)
					return false;
			}
		}
	}
	return true;
}

