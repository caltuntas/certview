#include <stdio.h>
#include "der.h"

void print_tlv_node(tlv_node_t *node,int indent) 
{
  const char *tag_number_str=tag_number_t_toString(node->tlv.tag.number);
  char str[20]={0};
  if(tag_number_str==NULL) {
    if(node->tlv.tag.class ==CONTEXT_SPECIFIC && node->tlv.tag.type ==CONSTRUCTED){
      sprintf(str,"[%d] EXPLICIT",node->tlv.tag.number);
      tag_number_str=str;
    } else if(node->tlv.tag.class ==CONTEXT_SPECIFIC){
      sprintf(str,"[%d]",node->tlv.tag.number);
      tag_number_str=str;
    }
  } else {
    if(node->tlv.tag.class ==CONTEXT_SPECIFIC && node->tlv.tag.type ==CONSTRUCTED){
      sprintf(str,"[%d] EXPLICIT",node->tlv.tag.number);
      tag_number_str=str;
    } 
  }
  const char *type_str=type_t_toString(node->tlv.tag.type);
  const char *class_str=class_t_toString(node->tlv.tag.class);
  printf("%*s %s(%s,len=%d):",indent,"",tag_number_str,type_str,node->tlv.len);
  if (node->count <= 0) {
    for(int i=0; i<node->tlv.len; i++) {
      printf("%02X,",*(node->tlv.value+i));
    }
  } else {
    for(int i=node->tlv.len_meta+2; i>0; i--) {
      printf("%02X,",*(node->tlv.value-i));
    }
  }
  printf("\n");
  for(int i=0; i<node->count; i++){
    print_tlv_node(&node->children[i],indent+1);
  }
}

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
