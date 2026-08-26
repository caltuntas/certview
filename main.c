#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <regex.h>
#include <netdb.h>
#include "asn1.h"
#include "der.h"

typedef struct html_header_t {
  char *buffer;
  size_t content_len;
  size_t header_len;
} html_header_t;

typedef struct html_body_t {
  char *buffer;
  size_t current_len;
  size_t len;
} html_body_t;

typedef struct html_response_t {
  html_header_t header;
  html_body_t body;
} html_response_t;

void html_parse_header(html_header_t *header,char *buffer)
{
  char *strptr=strstr(buffer,"\r\n\r\n");
  if(strptr==NULL)
    return;
  size_t header_len=strptr-buffer;
  header->buffer=malloc(sizeof(char)*header_len);
  header->header_len=header_len;
  memcpy(header->buffer,buffer,header_len);
  char *pattern="Content-Length: ([0-9]+)";
  regex_t regex;
  size_t max_match=2;
  regmatch_t match[max_match];
  if(regcomp(&regex,pattern,REG_EXTENDED)!=0) {
    perror("regex compilation has failed");
    exit(1);
  }
  if(regexec(&regex,header->buffer,max_match,match,0)==0){
    int start=match[1].rm_so;
    int end=match[1].rm_eo;
    int len=end-start;
    int content_len=strtol(header->buffer+start,NULL,10);
    header->content_len=content_len;
  }
}

void download()
{
  //http://i.cf-b.ssl.com/Cloudflare-TLS-I-E1.cer
  struct addrinfo hints={0}, *res, *res0;
  hints.ai_family=PF_UNSPEC;
  hints.ai_socktype=SOCK_STREAM;
  int error=getaddrinfo("i.cf-b.ssl.com","http",&hints,&res0);
  if(error) {
    fprintf(stderr,"error status=%s",gai_strerror(error));
    exit(1);
  }
  int s=socket(res0->ai_family,res0->ai_socktype,res0->ai_protocol);
  int c=connect(s,res0->ai_addr,res0->ai_addrlen);
  if(c<0) {
    printf("connection problem");
    exit(1);
  }
  char *http_get="GET /Cloudflare-TLS-I-E1.cer HTTP/1.1\r\n"
    "Host: i.cf-b.ssl.com\r\n"
    "User-Agent: Wget/1.25.0\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: identity\r\n"
    "Connection: close\r\n"
    "\r\n";
  size_t msglen=strlen(http_get);
  ssize_t bytes_sent=send(s,http_get,msglen,0);
  if(bytes_sent<0) {
    perror("send failed");
  }else if(bytes_sent<msglen) {
    printf("bytes < msglen \n");
  } else {
    printf("message sent\n");
  }
  char *reply=malloc(sizeof(*reply)*10000);
  ssize_t bytes_received=0;
  size_t total_bytes=0;
  html_response_t response={0};
  while(1){
    char buffer[1024];
    size_t buffer_size=sizeof(buffer)-1;
    bytes_received=recv(s,buffer,buffer_size,0);
    if(bytes_received<0){
      perror("recv failed");
    } else if(bytes_received==0) {
      perror("recv failed");
    } else {
      buffer[bytes_received]='\0';
      printf("server reply=%s\n",buffer);
    }
    memcpy(reply+total_bytes,buffer,bytes_received);
    total_bytes+=bytes_received;
    if(response.header.header_len==0) {
      html_parse_header(&response.header,reply);
      if(response.header.header_len>0) {
        response.body.buffer=malloc(sizeof(char)*response.header.content_len);
        memcpy(response.body.buffer,reply+response.header.header_len+4,total_bytes-response.header.header_len);
        response.body.current_len=total_bytes-response.header.header_len;
        response.body.len=response.header.content_len+4;

      }
    } else if (response.body.len!=0){
      memcpy(response.body.buffer+response.body.current_len-4,buffer,bytes_received);
      response.body.current_len+=bytes_received;
    }

    if(response.body.current_len>=response.body.len) {

      FILE *file = fopen("output.bin", "wb");
      if (file == NULL) {
        perror("Error opening file");
        exit(1);
      }

      size_t bytes_written = fwrite(response.body.buffer, sizeof(unsigned char), response.body.len,file);
      break;
    }
  }
}

int main(int argc, char **argv) 
{
  download();
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
