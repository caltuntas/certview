#include <stdio.h>
#include "der.h"
#include "asn1.h"



int main(int argc, char **argv) 
{
  char* file_name=argv[1];

  uint8_t *buffer;
  size_t len;
  FILE *file =fopen(file_name,"rb");
  if(file==NULL) {
    perror("fopen");
    return EXIT_FAILURE;
  }

  fseek(file,0,SEEK_END);
  len=ftell(file);
  fseek(file,0,SEEK_SET);
  buffer=malloc(len);
  if(buffer==NULL) {
    perror("malloc");
    fclose(file);
    return EXIT_FAILURE;
  }
  fread(buffer,1,len,file);
  fclose(file);

  tlv_t tlv = parse_tlv(buffer,len);
  tlv_node_t *root =build_tlv(tlv);
  field_t *parent=create_x509_definition();

  field_value_t *mapping=NULL;
  bool is_valid=validate_schema(parent,root,&mapping);
  decoder_t basic_const_decoder={0};
  basic_const_decoder.field_value_type=OCTET_STRING;
  basic_const_decoder.decoder_func=decode_basic_constraints;
	decode(mapping,&basic_const_decoder);
  print_debug(is_valid,buffer,len,root,parent,mapping);

  return EXIT_SUCCESS;
}
