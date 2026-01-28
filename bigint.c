#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "bigint.h"

bigint_t *create_bigint(uint8_t *buf,size_t len)
{
  bigint_t *bigint =malloc(sizeof(*bigint));
  bigint->sign=(buf[0] & 0x80)==0x80;
  bigint->data=malloc(sizeof(uint8_t)*len);
  memcpy(bigint->data,buf,len);
  bigint->length=len;
  return bigint;
}

char *add(char *x, char *y,int base)
{
  int obase=base;
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

bigint_t *add_bigint(bigint_t *num1, bigint_t *num2)
{
  bigint_t *bi=malloc(sizeof(*bi));
  int obase=256;
  int len_x=num1->length;
  int len_y=num2->length;
  uint8_t *res=calloc(len_x+len_y+2,sizeof(char));
  bi->data=res;
  int carry=0;
  int len=len_x>len_y?len_x:len_y;
  int diff=abs(len_x-len_y);
  int counter=0;
  for (int i=len-1; i>=0; i--){
    int digit_y=0;
    int digit_x=0;
    int d=i-diff;

    if(len_x>len_y) {
      digit_x=num1->data[i];
      if(d>=0)
        digit_y=num2->data[i-diff];
    } else if (len_x<len_y) {
      if(d>=0)
        digit_x=num1->data[i-diff];
      digit_y=num2->data[i];
    } else {
      digit_x=num1->data[i];
      digit_y=num2->data[i];
    }

    int mul=digit_x+digit_y+carry;
    carry=0;
    int c=0; 
    c=mul / obase; 
    carry+=c;
    int digit=mul % obase;
    memmove(res+1, res, len+1);
    res[0]=digit;
    if(i==0 && c!=0){
      memmove(res+1, res, len+1);
      res[0]=c;
      bi->length++;
    }
    bi->length++;
  }
  return bi;
}

char *mul(char *x, char *y,int base)
{
  int obase=base;
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
      //printf("%d x %d = %d\n",digit_y,digit_x,mul);
      //printf("carry=%d , digit=%d\n",c,digit);
    }
    for(int k=0; k<counter; k++) {
      strncat(res,"0",1);
    }
    //printf("res=%s\n",res);
    total=add(total,res,base);
    memset(res,0,len_x+len_y+2);
    counter++;
  }
  return total;
}

bigint_t *mul_bigint(bigint_t *num1, bigint_t *num2)
{
  int len_x=num1->length;
  int len_y=num2->length;
  bigint_t *bi=malloc(sizeof(*bi));
  uint8_t *res=calloc(len_x+len_y+2,sizeof(uint8_t));
  bi->data=res;
  bigint_t *total=malloc(sizeof(*total));
  uint8_t *restotal=calloc(len_x+len_y+2,sizeof(uint8_t));
  total->data=restotal;
  int obase=256;
  int carry=0;
  int counter=0;
  for (int i=len_y-1; i>=0; i--){
    for (int j=len_x-1; j>=0; j--){
      uint8_t digit_y=num2->data[i];
      uint8_t digit_x=num1->data[j];
      int mul=digit_x*digit_y+carry;
      carry=0;
      int c=0; 
      c=mul / obase; 

      carry+=c;
      int digit=mul % obase;
      memmove(res+1, res, len_x+1);
      res[0]=digit;
      bi->length++;
      if(j==0 && c!=0){
        memmove(res+1, res, len_x+1);
        res[0]=c;
        bi->length++;
        carry=0;
      }
    }
    for(int k=0; k<counter; k++) {
      res[bi->length]=0;
      bi->length++;
    }
    bigint_t *restotal=add_bigint(total,bi);
    total=restotal;
    memset(res,0,len_x+len_y+2);
    bi->length=0;
    counter++;
  }
  return total;
}

void ltrim(char *str,char chr)
{
  char *ptr =str;
  int len=strlen(str);
  while(*ptr && *ptr==chr) {
    ++ptr, --len;
  }
  memmove(str, ptr, len + 1);
}

void bigint_ltrim(bigint_t *bi,uint8_t val)
{
  uint8_t *ptr =bi->data;
  size_t len=bi->length;
  while(len>0 && ptr!=NULL && *ptr==val) {
    ++ptr, --len;
  }
  bi->length=len;
  memmove(bi->data, ptr, len + 1);
}

//https://en.wikipedia.org/wiki/Horner%27s_method
char *hex_to_decimal_str(uint8_t *hex,size_t len)
{
  bool is_negative=false;
  //check if it is negative
  if((hex[0] & 0x80)==0x80) {
    is_negative=true;
  }
  int obase=10;
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
      res=add(mul(num1,ibase_str,obase),num2,obase);
    }else {
      res=add(mul(res,ibase_str,obase),num1,obase);
      res=add(mul(res,ibase_str,obase),num2,obase);
    }
  }
  //https://en.wikipedia.org/wiki/Two%27s_complement
  if(is_negative) {
    uint8_t *inc=calloc(len+1,sizeof(uint8_t));
    inc[0]=1;
    char *val=hex_to_decimal_str(inc,len+1);
    char *result=sub(res,val);
    ltrim(result,'0');
    return result;
  }
  ltrim(res,'0');
  return res;
}

//https://en.wikipedia.org/wiki/Horner%27s_method
char *bigint_to_decimal_str(bigint_t *num)
{
  bool is_negative=false;
  //check if it is negative
  if((num->data[0] & 0x80)==0x80) {
    is_negative=true;
  }
  int obase=10;
  char *ibase_str="16";
  int total;
  char *res=NULL;
  for(int i=0; i<num->length; i++){
    int part1=(num->data[i] >> 4) & 0x0F;
    int part2=(num->data[i]) & 0x0F;
    char num1[10];
    sprintf(num1,"%d",part1);
    char num2[10];
    sprintf(num2,"%d",part2);
    if(i==0){
      res=add(mul(num1,ibase_str,obase),num2,obase);
    }else {
      res=add(mul(res,ibase_str,obase),num1,obase);
      res=add(mul(res,ibase_str,obase),num2,obase);
    }
  }
  //https://en.wikipedia.org/wiki/Two%27s_complement
  if(is_negative) {
    uint8_t *inc=calloc(num->length+1,sizeof(uint8_t));
    inc[0]=1;
    char *val=hex_to_decimal_str(inc,num->length+1);
    char *result=sub(res,val);
    ltrim(result,'0');
    return result;
  }
  ltrim(res,'0');
  return res;
}

int compare(char *x, char *y)
{
  size_t lenx=strlen(x);
  size_t leny=strlen(y);
  if(lenx<leny)
    return -1;
  else if(lenx>leny)
    return 1;
  int cmp=strcmp(x,y);
  if(cmp>0) return 1;
  else if(cmp<0) return -1;
  else return 0;
}

int compare_bigint(bigint_t *num1, bigint_t *num2)
{
  size_t lenx=num1->length;
  size_t leny=num2->length;
  if(lenx<leny)
    return -1;
  else if(lenx>leny)
    return 1;
  int cmp=memcmp(num1->data,num2->data,lenx);
  if(cmp>0) return 1;
  else if(cmp<0) return -1;
  else return 0;
}

char *sub(char *x, char *y)
{
  char *str1;
  char *str2;
  int cmp=compare(x,y);
  bool is_negative=false;
  if (cmp<0) {
    is_negative=true;
    str1=y;
    str2=x;
  } else if (cmp > 0) {
    is_negative=false;
    str1=x;
    str2=y;
  }

  int obase=10;
  int len1=strlen(str1);
  int len2=strlen(str2);
  char *res=calloc(len1+len2+2,sizeof(char));
  int borrow=0;
  int len=len1>len2?len1:len2;
  int diff=abs(len1-len2);
  for (int i=len-1; i>=0; i--){
    int digit_y=0;
    int digit_x=0;
    int d=i-diff;

    if(len1>len2) {
      digit_x=str1[i]-'0';
      if(d>=0)
        digit_y=str2[i-diff]-'0';
    } else if (len1<len2) {
      if(d>=0)
        digit_x=str1[i-diff]-'0';
      digit_y=str2[i]-'0';
    } else {
      digit_x=str1[i]-'0';
      digit_y=str2[i]-'0';
    }

    digit_x=digit_x-borrow;
    if(digit_x<digit_y)
      borrow=1;
    else 
      borrow=0;
    int sub=(borrow*obase+digit_x)-digit_y;
    int digit=sub % obase;
    if(digit==0 && i==0){
      break;
    }
    char *str=strdup(res);
    char chr=digit+'0';
    strncpy(res,&chr,1);
    strcpy(res+1,str);
  }
  ltrim(res,'0');
  if(is_negative) {
    len=strlen(res);
    memmove(res+1, res, len+1);
    res[0]='-';
  }
  return res;
}

bigint_t *sub_bigint(bigint_t *num1,bigint_t *num2)
{
  bigint_t *n1;
  bigint_t *n2;
  int cmp=compare_bigint(num1,num2);
  bool is_negative=false;
  if (cmp<0) {
    is_negative=true;
    n1=num2;
    n2=num1;
  } else if (cmp > 0) {
    is_negative=false;
    n1=num1;
    n2=num2;
  }

  int obase=256;
  int len1=n1->length;
  int len2=n2->length;
  bigint_t *bigint =malloc(sizeof(*bigint));
  uint8_t *res=calloc(len1+len2+2,sizeof(char));
  bigint->data=res;
  int borrow=0;
  int len=len1>len2?len1:len2;
  int diff=abs(len1-len2);
  for (int i=len-1; i>=0; i--){
    int digit_y=0;
    int digit_x=0;
    int d=i-diff;
    if(len1>len2) {
      digit_x=n1->data[i];
      if(d>=0)
        digit_y=n2->data[i-diff];
    } else if (len1<len2) {
      if(d>=0)
        digit_x=n1->data[i-diff];
      digit_y=n2->data[i];
    } else {
      digit_x=n1->data[i];
      digit_y=n2->data[i];
    }

    digit_x=digit_x-borrow;
    if(digit_x<digit_y)
      borrow=1;
    else 
      borrow=0;
    int sub=(borrow*obase+digit_x)-digit_y;
    int digit=sub % obase;
    if(digit==0 && i==0){
      break;
    }
    memmove(res+1, res, len+1);
    res[0]=digit;
    bigint->length++;
    //char *str=strdup(res);
    //char chr=digit+'0';
    //strncpy(res,&chr,1);
    //strcpy(res+1,str);
  }
  bigint_ltrim(bigint,0);
  //if(is_negative) {
  //  len=strlen(res);
  //  memmove(res+1, res, len+1);
  //  res[0]='-';
  //}
  return bigint;
}

bigint_t *bigint_from_decimal_str(char *decimal)
{
  bigint_t *bi=malloc(sizeof(*bi));
  bool is_negative=false;
  bigint_t *res=NULL;
  int obase=256;
  int len=strlen(decimal);
  uint8_t ten[]={10};
  bigint_t *ibase=create_bigint(ten,1);
  if(len==1) {
    uint8_t d1=decimal[0]-'0';
    res=create_bigint(&d1,1);
  } else {
    for(int i=0; i<len-1; i++){
      uint8_t d1=decimal[i]-'0';
      bigint_t *num1=create_bigint(&d1,1);
      uint8_t d2=decimal[i+1]-'0';
      bigint_t *num2=create_bigint(&d2,1);
      bigint_t *mulres=NULL;
      if (i==0) {
        mulres=mul_bigint(num1,ibase);
        res=add_bigint(mulres,num2);
      }else {
        mulres=mul_bigint(res,ibase);
        res=add_bigint(mulres,num2);
      }
    }
  }
  return res;
}
