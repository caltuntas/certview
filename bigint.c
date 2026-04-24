#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "bigint.h"

bool bigint_is_zero(bigint_t *num)
{
  if(num!=NULL && num->length==1 && num->data[0]==0)
    return true;
  return false;
}

bigint_t *create_bigint(uint8_t *buf,size_t len)
{
  bigint_t *bigint =malloc(sizeof(*bigint));
  if((buf[0] & 0x80)==0x80)
    bigint->sign=NEGATIVE;
  else
    bigint->sign=NON_NEGATIVE;
  bigint->data=malloc(sizeof(uint8_t)*len);
  memcpy(bigint->data,buf,len);
  bigint->length=len;
  if(bigint->sign==NEGATIVE) {
    uint8_t *inc=calloc(len+1,sizeof(uint8_t));
    inc[0]=1;
    bigint_t *next2=create_bigint(inc,len+1);
    next2->sign=NEGATIVE;
    bigint_t *result=sub_bigint(next2,bigint);
    result->sign=NEGATIVE;
    bigint_ltrim(result,0);
    return result;
  }
  bigint_ltrim(bigint,0);
  return bigint;
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
  int cmp=compare_bigint(num1,num2);
  bool first_is_bigger=true;
  if (cmp<0) {
    first_is_bigger=false;
  } else if (cmp > 0) {
    first_is_bigger=true;
  } 
  if(num1->sign!=num2->sign){
    int s1=num1->sign;
    int s2=num2->sign;
    num1->sign=NON_NEGATIVE;
    num2->sign=NON_NEGATIVE;
    bigint_t *subres=sub_bigint(num1,num2);
    num1->sign=s1;
    num2->sign=s2;
    if(first_is_bigger)
      subres->sign=num1->sign;
    else
      subres->sign=num2->sign;
    if(bigint_is_zero(subres))
      subres->sign=NON_NEGATIVE;
    return subres;
  }
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
  bigint_ltrim(bi,0);
  bi->sign=num1->sign;
  if(bigint_is_zero(bi))
    bi->sign=NON_NEGATIVE;
  return bi;
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
  while(len>1 && ptr!=NULL && *ptr==val) {
    ++ptr, --len;
  }
  bi->length=len;
  memmove(bi->data, ptr, len + 1);
}

static bool is_empty(uint8_t *buf,size_t len)
{
  for(int i=0; i<len; i++){
    if(buf[i]!=0)
      return false;
  }
  return true;
}

//https://en.wikipedia.org/wiki/Long_division
char *bigint_to_decimal_str(bigint_t *num)
{
  int obase=10;
  int ibase=256;
  char *ibase_str="16";
  int total;
  int carry=0;
  char *res=calloc(num->length*5,sizeof(char));;
  if(bigint_is_zero(num)){
    *res='0';
    return res;
  }

  uint8_t *arr=calloc(num->length,sizeof(uint8_t));
  memcpy(arr,num->data,num->length);
  while(is_empty(arr,num->length)==false){
    int remainder=0;
    for(int i=0; i<num->length; i++){
      carry=arr[i] + remainder*ibase;
      int quotient=carry / obase;
      remainder=carry % obase;
      arr[i]=quotient;
    }
    char num1[10];
    sprintf(num1,"%d",remainder);
    int nlen=strlen(num1);
    int rlen=strlen(res);
    //TODO:create a dedicated string type and add push function
    memmove(res+nlen, res, rlen);
    memcpy(res,num1,nlen);
  }
  ltrim(res,'0');
  if(num->sign==NEGATIVE) {
    size_t len=strlen(res);
    memmove(res+1, res, len+1);
    res[0]='-';
    return res;
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
  if(num1->sign!=num2->sign){
    int s1=num1->sign;
    int s2=num2->sign;
    num1->sign=NON_NEGATIVE;
    num2->sign=NON_NEGATIVE;
    bigint_t *res=add_bigint(num1,num2);
    num1->sign=s1;
    num2->sign=s2;
    res->sign=s1;
    return res;
  }
  int cmp=compare_bigint(num1,num2);
  bool first_is_bigger=true;
  if (cmp<0) {
    first_is_bigger=false;
    n1=num2;
    n2=num1;
  } else if (cmp > 0) {
    first_is_bigger=true;
    n1=num1;
    n2=num2;
  } else {
    return create_bigint((uint8_t[]){0},1);
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
  }
  bigint_ltrim(bigint,0);
  if(first_is_bigger)
    bigint->sign=num1->sign;
  else 
    bigint->sign=NEGATIVE*num1->sign;
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
  ibase->sign=NON_NEGATIVE;
  if(len==1) {
    uint8_t d1=decimal[0]-'0';
    res=create_bigint(&d1,1);
  } else {
    for(int i=0; i<len-1; i++){
      uint8_t d1=decimal[i]-'0';
      bigint_t *num1=create_bigint(&d1,1);
      num1->sign=NON_NEGATIVE;
      uint8_t d2=decimal[i+1]-'0';
      bigint_t *num2=create_bigint(&d2,1);
      num2->sign=NON_NEGATIVE;
      bigint_t *mulres=NULL;
      if (i==0) {
        mulres=mul_bigint(num1,ibase);
        mulres->sign=NON_NEGATIVE;
        res=add_bigint(mulres,num2);
      }else {
        mulres=mul_bigint(res,ibase);
        mulres->sign=NON_NEGATIVE;
        res=add_bigint(mulres,num2);
      }
    }
  }
  return res;
}

//https://ridiculousfish.com/blog/posts/labor-of-division-episode-iv.html
//https://skanthak.hier-im-netz.de/division.html
//https://www.hvks.com/Numerical/Downloads/HVE%20The%20Math%20behind%20arbitrary%20precision.pdf
bigint_t *div_bigint(bigint_t *num1, bigint_t *num2, bigint_t **remainder)
{
  int len_dividend=num1->length;
  int len_divisor=num2->length;
  int len_diff=len_dividend-len_divisor;
  int target_len=len_diff+len_divisor+1;
  int base=256;
  int d=0;

  uint8_t *res=calloc(len_diff+1,sizeof(*res));

  if(len_divisor==1) {
    uint16_t rem=0;
    for(int i=0; i<len_dividend; i++){
      uint16_t numerator=(rem * base) + num1->data[i];
      uint16_t q=numerator / num2->data[0];
      rem=numerator % num2->data[0];
      printf("q=%d,r=%d\n",q,rem);
      res[i]=q;
    }

    if(remainder!=NULL) {
      bigint_t *r=malloc(sizeof(*r));
      r->data=calloc(1,sizeof(uint8_t));
      r->data[0]=rem;
      r->length=1;
      bigint_ltrim(r,0);
      bigint_t *v=shift_right_bigint(r,d);
      v->sign=num1->sign;
      if(bigint_is_zero(v))
        v->sign=NON_NEGATIVE;
      *remainder=v;
    }

    bigint_t *bi=malloc(sizeof(*bi));
    bi->sign = num1->sign * num2->sign;
    bi->data=res;
    bi->length=len_diff+1;
    bigint_ltrim(bi,0);
    if(bigint_is_zero(bi))
      bi->sign=NON_NEGATIVE;
    return bi;
  }

  for(int i=7; i>=0; i--){
    int is_zero=(num2->data[0] >> i) & 1;
    if(is_zero==0)
      d++;
    else
      break;
  }
  bigint_t *U=shift_left_bigint(num1,d);
  int udiff=target_len-U->length;
  uint8_t *Ubuf=calloc(target_len,sizeof(*Ubuf));
  memcpy(Ubuf+udiff,U->data,U->length);

  bigint_t *u=malloc(sizeof(*u));
  u->data=Ubuf;
  u->length=target_len;

  bigint_t *v=shift_left_bigint(num2,d);


  for(int j=0; j<=len_diff; j++){
    uint16_t numerator=(u->data[j] * base) + u->data[j+1];
    uint16_t q=numerator / v->data[0];
    uint16_t r=numerator % v->data[0];
    printf("q=%d,r=%d\n",q,r);

    while(q==base || q*v->data[1] > (r * base) + u->data[j+2]) {
      q--;
      r+=v->data[0];
    }

    uint8_t arr[]={0,q};
    bigint_t *qbi=create_bigint(arr,2);
    bigint_t *mulres=mul_bigint(qbi,v);

    bigint_t *Uslice=malloc(sizeof(*Uslice));
    Uslice->length=len_divisor+1;
    uint8_t *slicebuf=calloc(Uslice->length,sizeof(*slicebuf));
    memcpy(slicebuf,u->data+j,Uslice->length);
    Uslice->data=slicebuf;

    bigint_t *subres=sub_bigint(Uslice,mulres);

    uint8_t *buf=calloc(Uslice->length,sizeof(*slicebuf));
    int diff=Uslice->length-subres->length;
    memcpy(buf+diff, subres->data, subres->length);
    memcpy(u->data + j, buf,Uslice->length);

    printf("q[%d]=%d\n",j,q);
    res[j]=q;
  }

  printf("final u[]=");
  for(int i=0; i<target_len; i++){
    printf("%02X,",u->data[i]);
  }

  if(remainder!=NULL) {
    bigint_t *r=malloc(sizeof(*r));
    r->data=u->data;
    r->length=target_len;
    bigint_t *v=shift_right_bigint(r,d);
    bigint_ltrim(v,0);
    v->sign=num1->sign;
    if(bigint_is_zero(v))
      v->sign=NON_NEGATIVE;
    *remainder=v;
  }

  bigint_t *bi=malloc(sizeof(*bi));
  bi->data=res;
  bi->sign = num1->sign * num2->sign;
  bi->length=len_diff+1;
  bigint_ltrim(bi,0);
  if(bigint_is_zero(bi))
    bi->sign=NON_NEGATIVE;
  return bi;
}

bigint_t *shift_left_bigint(bigint_t *num1,int bits)
{
  bigint_t *bi=malloc(sizeof(*bi));
  int new_bytes=bits / 8;
  int shift_size=bits % 8;
  //pre-allocate possible carry byte in advance
  size_t len=num1->length+new_bytes+1;
  uint8_t *res=calloc(len,sizeof(*res));
  bi->data=res;
  uint8_t carry=0;
  for(int i=num1->length-1; i>=0; i--){
    uint8_t old_num=num1->data[i];
    uint8_t new_num=old_num << shift_size;
    bi->data[i]=new_num | carry;
    carry=(old_num >> (8-shift_size));
  }
  bi->length=len;
  if(carry!=0){
    memmove(bi->data+1, bi->data, bi->length);
    bi->data[0]=carry;
  }else {
    //reduce the pre-allocated carry length, if there is no carry byte
    bi->length-=1;
  }
  return bi;
}

bigint_t *shift_right_bigint(bigint_t *num1,int bits)
{
  bigint_t *bi=malloc(sizeof(*bi));
  int disposed_bytes=bits / 8;
  int shift_size=bits % 8;
  if(shift_size==0 && bits!=0)
    shift_size=8;

  size_t len=0;
  if(disposed_bytes>=num1->length){
    len=1;
  }else{
    len=num1->length-disposed_bytes;
  }
  uint8_t *res=calloc(len,sizeof(*res));
  bi->data=res;
  uint8_t carry=0;
  for(int i=0; i<num1->length; i++){
    uint8_t old_num=num1->data[i];
    uint8_t new_num=old_num >> shift_size;
    bi->data[i]=new_num | carry;
    carry=(old_num << (8-shift_size));
  }
  bi->length=len;
  if(disposed_bytes!=0 && shift_size==8){
    memmove(bi->data, bi->data+disposed_bytes, bi->length);
  }
  return bi;
}

bigint_t *mod_bigint(bigint_t *num1, bigint_t *num2)
{
  bigint_t *remainder=NULL;
  bigint_t *quotient =div_bigint(num1,num2,&remainder);
  if(remainder->sign==NEGATIVE) {
    bigint_t *res=add_bigint(remainder,num2);
    return res;
  }
  return remainder;
}
