#include <stdio.h>
#include "ecdsa.h"

int ecdsa_mod(int num, unsigned int divisor) 
{
	if(num>=0){
		return num % divisor;
	}else {
		int n=num+divisor;
		return ecdsa_mod(n,divisor);
	}
}

int ecdsa_gcd(int dividend, int divisor) 
{
  if(divisor==0)
    return dividend;
  if(dividend==0)
    return divisor;
  int cur_dividend=dividend, cur_divisor=divisor,res;
  while((res=cur_dividend % cur_divisor)!=0) {
    cur_dividend=cur_divisor;
    cur_divisor=res;
  } 
  return cur_divisor;
}

xgcd_result_t ecdsa_xgcd(int dividend, int divisor)
{
  int xi=0,xi1=0,xi2=0;
  int yi=0,yi1=0,yi2=0;
  int qi2=0;
  int q=0;
  int g=0;
  if(divisor==0)
    g=dividend;
  int step=0;
  int i=0;
  xgcd_result_t result;
  int cur_dividend=dividend, cur_divisor=divisor,r;
  while(cur_divisor!=0) {
		printf("loop xi=%d,xi1=%d,xi2=%d,yi=%d,yi1=%d,yi2=%d\n",xi,xi1,xi2,yi,yi1,yi2);
    r=cur_dividend % cur_divisor;
    if(r==0)
      g=cur_divisor;
    if(step==0) {
      xi=1;
      yi=0;
    }else if(step==1) {
      xi=0;
      yi=1;
    }else {
      xi=xi2-qi2*xi1;
      yi=yi2-qi2*yi1;
    }
    qi2=q;
    q=cur_dividend / cur_divisor;
    cur_dividend=cur_divisor;
    cur_divisor=r;
		printf("loop dividend=%d,divisor=%d,q=%d,r=%d\n",cur_dividend,cur_divisor,q,r);
    step++;
    xi2=xi1;
    yi2=yi1;
    xi1=xi;
    yi1=yi;
  } 
  if(step==0) {
    xi=1;
    yi=0;
  }else if(step==1) {
    xi=0;
    yi=1;
  }else {
    xi=xi2-qi2*xi1;
    yi=yi2-qi2*yi1;
  }
	printf("outside xi=%d,xi1=%d,xi2=%d,yi=%d,yi1=%d,yi2=%d\n",xi,xi1,xi2,yi,yi1,yi2);
  if(g<0){
    g*=-1;
    xi*=-1;
    yi*=-1;
  }
  result.g=g;
  result.x=xi;
  result.y=yi;
  return result;
}

//TODO:revisit error handling later, 0 might be a valid result mathematically
/*
 * returns 0 for no inverse case
 */
int ecdsa_mod_inverse(int num, unsigned int divisor) 
{
  xgcd_result_t result=ecdsa_xgcd(num,divisor);
  if(result.g!=1)
    return 0;
  int mod=ecdsa_mod(result.x,divisor);
	return mod;
}

//https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/
ecdsa_point_t ecdsa_point_double(ecdsa_params_t params, ecdsa_point_t p)
{
	int slope=ecdsa_mod(3*p.x*p.x+params.a,params.p)*ecdsa_mod_inverse(2*p.y,params.p);
	slope=ecdsa_mod(slope,params.p);
	int x=ecdsa_mod(slope*slope-2*p.x,params.p);
	int y=ecdsa_mod(slope*(p.x-x)-p.y,params.p);
	ecdsa_point_t result={x,y};
	return result;
}

ecdsa_point_t ecdsa_point_times(ecdsa_params_t params, int times,ecdsa_point_t p)
{
	ecdsa_point_t result={.is_infinity=true};
	ecdsa_point_t current=p;
  for(int i=0; i<sizeof(times)*8; i++){
    bool is_bit_set=((times>>i)&1);
    if(is_bit_set){
      result = ecdsa_point_add(params,result,current);
    }
    current = ecdsa_point_double(params,current);
  }
	return result;
}

ecdsa_point_t ecdsa_point_add(ecdsa_params_t params, ecdsa_point_t p1, ecdsa_point_t p2)
{
  if(p1.is_infinity)
    return (ecdsa_point_t){p2.x,p2.y};
  if(p2.is_infinity)
    return (ecdsa_point_t){p1.x,p1.y};
  if(p1.x==p2.x && p1.y!=p2.y)
    return (ecdsa_point_t){.is_infinity=true};
	int slope=ecdsa_mod(p2.y-p1.y,params.p)*ecdsa_mod_inverse(ecdsa_mod(p2.x-p1.x,params.p),params.p);
	slope=ecdsa_mod(slope,params.p);
	int x=ecdsa_mod(slope*slope-p1.x-p2.x,params.p);
	int y=ecdsa_mod(slope*(p1.x-x)-p1.y,params.p);
	ecdsa_point_t result={x,y};
	return result;
}

bool ecdsa_signature_verify(ecdsa_params_t params, ecdsa_signature_t sig,int z,ecdsa_point_t q)
{
	int w = ecdsa_mod_inverse(sig.s,params.n);
	int u1=ecdsa_mod(z*w,params.n);
	int u2=ecdsa_mod(sig.r*w,params.n);
	ecdsa_point_t tmp1=ecdsa_point_times(params,u1,params.g);
	ecdsa_point_t tmp2=ecdsa_point_times(params,u2,q);
	ecdsa_point_t p=ecdsa_point_add(params,tmp1,tmp2);
	return ecdsa_mod(p.x,params.n)==sig.r;
}
