#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "bigint.h"

bigint_t *create_bigint(uint8_t *buf,size_t len)
{
  bigint_t *bigint =malloc(sizeof(*bigint));
  bigint->sign=(buf[0] & 0x80)==0x80;
  return bigint;
}

char *bigint_to_decimal_str(bigint_t *bigint)
{
  return "0";
}

char *add(char *x, char *y)
{
  int obase=10;
  int len_x=strlen(x);
  int len_y=strlen(y);
  char *res=calloc(len_x+len_y+2,sizeof(char));
  int carry=0;
  int len=len_x>len_y?len_x:len_y;
  int diff=abs(len_x-len_y);
  for (int i=len-1; i>=0; i--){
    int digit_y=0;
    int digit_x=0;
    int d=i-diff;

    if(len_x>len_y) {
      digit_x=x[i]-'0';
      if(d>=0)
        digit_y=y[i-diff]-'0';
    } else if (len_x<len_y) {
      if(d>=0)
        digit_x=x[i-diff]-'0';
      digit_y=y[i]-'0';
    } else {
      digit_x=x[i]-'0';
      digit_y=y[i]-'0';
    }

    int mul=digit_x+digit_y+carry;
    carry=0;
    int c=0; 
    c=mul / obase; 
    carry+=c;
    int digit=mul % obase;
    char *str=strdup(res);
    char chr=digit+'0';
    strncpy(res,&chr,1);
    strcpy(res+1,str);
    if(i==0 && c!=0){
      char *str1=strdup(res);
      char chr1=c+'0';
      strncpy(res,&chr1,1);
      strcpy(res+1,str1);
    }
  }
  return res;
}

char *mul(char *x, char *y)
{
  int obase=10;
  int len_x=strlen(x);
  int len_y=strlen(y);
  char *res=calloc(len_x+len_y+2,sizeof(char));
  char *total="0";
  int carry=0;
  int counter=0;
  for (int i=len_y-1; i>=0; i--){
    for (int j=len_x-1; j>=0; j--){
      int digit_y=y[i]-'0';
      int digit_x=x[j]-'0';
      int mul=digit_x*digit_y+carry;
      carry=0;
      int c=0; 
      c=mul / obase; 

      carry+=c;
      int digit=mul % obase;
      char *str=strdup(res);
      char chr=digit+'0';
      strncpy(res,&chr,1);
      strcpy(res+1,str);

      if(j==0 && c!=0){
        char *str1=strdup(res);
        char chr1=c+'0';
        strncpy(res,&chr1,1);
        strcpy(res+1,str1);
        carry=0;
      }
      printf("%d x %d = %d\n",digit_y,digit_x,mul);
      printf("carry=%d , digit=%d\n",c,digit);
    }
    for(int k=0; k<counter; k++) {
      strncat(res,"0",1);
    }
    printf("res=%s\n",res);
    total=add(total,res);
    memset(res,0,len_x+len_y+2);
    counter++;
  }
  return total;
}

//https://en.wikipedia.org/wiki/Horner%27s_method
char *hex_to_decimal_str(uint8_t *hex,size_t len)
{
  int ibase=16;
  char *ibase_str="16";
  int total;
  char *res=NULL;
  for(int i=0; i<len; i++){
    int part1=(hex[i] >> 4) & 0x0F;
    int part2=(hex[i]) & 0x0F;
    char num1[10];
    sprintf(num1,"%d",part1);
    char num2[10];
    sprintf(num2,"%d",part2);
    if(i==0){
      //total=part1*ibase+part2;
      res=add(mul(num1,ibase_str),num2);
    }else {
      //total=total*ibase+part1;
      //total=total*ibase+part2;
      res=add(mul(res,ibase_str),num1);
      res=add(mul(res,ibase_str),num2);
    }
  }
  return res;
}

