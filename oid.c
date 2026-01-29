#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "oid.h"

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
	return "";
}
