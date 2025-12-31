#include <stdio.h>
#include "der.h"



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

  print_tlv_node(root,0);

  return EXIT_SUCCESS;
}
