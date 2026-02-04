#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "oid.h"



//TODO:error hangling
//TODO:unterminated buffer
//TODO:edge cases
oid_t *oid_create(uint8_t *buf,size_t len)
{
	oid_t *oid =malloc(sizeof(*oid));
	oid->buffer=calloc(len,sizeof(uint8_t));
	memcpy(oid->buffer,buf,len);
	oid->length=len;
	oid->arcs=calloc(100,sizeof(uint64_t));
	uint8_t byte=buf[0];
	uint64_t arc1=byte / 40;
	uint64_t arc2=byte % 40;
	oid->arcs[oid->arc_count++]=arc1;
	oid->arcs[oid->arc_count++]=arc2;

	int i=1;
	while(i<len) {
		uint64_t total=0;
		short continues=1;
		do {
			uint8_t nb=buf[i];
			continues=nb & 0x80;
			uint8_t val=nb & 0x7F;
			total=total+val;
			if(continues)
				total=total*128;
			i++;
		} while(continues) ;
		oid->arcs[oid->arc_count++]=total;
	}
	return oid;
}

char *oid_to_str(oid_t *oid)
{
  char dot[2]={0};
  dot[0]='.';
  dot[1]='\0';
  char *res=calloc(oid->arc_count,sizeof(char)*20);
  for(int i=0; i<oid->arc_count; i++){
    uint64_t arc=oid->arcs[i];
    char arc_str[20]={0};
    sprintf(arc_str,"%llu",arc);
    strcat(res,arc_str);
    if(i<oid->arc_count-1)
      strcat(res,dot);
  }
	return res;
}

oid_registry_t *oid_registry_create_entry(uint64_t arc,char *code, char *name)
{
  oid_registry_t *root=calloc(1,sizeof(*root));
  root->arc=arc;
  root->code=code;
  root->name=name;
  return root;
}

void add_oid_registry_entry(oid_registry_t *parent, oid_registry_t *child)
{
  size_t cnt=parent->count;
  parent->children=realloc(parent->children,sizeof(oid_registry_t*)*(parent->count+1));
  parent->children[cnt]=child;
  parent->count+=1;
}

oid_registry_t *oid_registry_create()
{
  oid_registry_t *root=calloc(1,sizeof(*root));
  oid_registry_t *child1=oid_registry_create_entry(1,"iso","ISO");
  oid_registry_t *child2=oid_registry_create_entry(2,"member-body","MEMBER BODY");
  oid_registry_t *child3=oid_registry_create_entry(840,"iso-us","ISO US");
  oid_registry_t *child4=oid_registry_create_entry(113549,"rsadsi","RSA DSI");
  oid_registry_t *child5=oid_registry_create_entry(1,"pkcs","PKCS");
  oid_registry_t *child6=oid_registry_create_entry(1,"pkcs1","PKCS");
  oid_registry_t *child7=oid_registry_create_entry(5,"sha1WithRSAEncryption","SHA1 with RSA");
  add_oid_registry_entry(root,child1);
  add_oid_registry_entry(child1,child2);
  add_oid_registry_entry(child2,child3);
  add_oid_registry_entry(child3,child4);
  add_oid_registry_entry(child4,child5);
  add_oid_registry_entry(child5,child6);
  add_oid_registry_entry(child6,child7);
  return root;
}

char *oid_to_reg_str(oid_t *oid)
{
  char dot[2]={0};
  dot[0]='.';
  dot[1]='\0';
  char *res=calloc(200,sizeof(char));
  oid_registry_t *root=oid_registry_create();
  oid_registry_t *reg=root;
  for(int i=0; i<oid->arc_count; i++){
    uint64_t arc=oid->arcs[i];
    char arc_str[50]={0};
    sprintf(arc_str,"%llu",arc);
    strcat(res,arc_str);
    for(int j=0; reg!=NULL && j<reg->count; j++){
      oid_registry_t *sub_reg=reg->children[j];
      if(sub_reg->arc==arc){
        reg=sub_reg;
        char code_str[50]={0};
        sprintf(code_str,"(%s)",sub_reg->code);
        strcat(res,code_str);
        break;
      }else {
        reg=NULL;
      }
    }
    if(i<oid->arc_count-1)
      strcat(res,dot);
  }
	return res;
}
