#include <stdio.h>
#include "ecdsa.h"

/*
int ecdsa_mod(int num, unsigned int divisor) 
{
	if(num>=0){
		return num % divisor;
	}else {
		int n=num+divisor;
		return ecdsa_mod(n,divisor);
	}
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
*/

//https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/
ecdsa_point_t ecdsa_point_double(ecdsa_params_t params, ecdsa_point_t p)
{
	bigint_t *three=create_bigint_from_int(3);
	bigint_t *two=create_bigint_from_int(2);
	bigint_t *px2=mul_bigint(p.x,p.x);
	bigint_t *px2three=mul_bigint(three,px2);
	bigint_t *px2threeplusa=add_bigint(px2three,params.a);
	bigint_t *twomulpy=mul_bigint(two,p.y);

	bigint_t *slope=mul_bigint(mod_bigint(px2threeplusa,params.p),mod_inverse(twomulpy,params.p));
	slope=mod_bigint(slope,params.p);
	bigint_t *slope2=mul_bigint(slope,slope);
	bigint_t *twomulpx=mul_bigint(two,p.x);
	bigint_t *x=mod_bigint(sub_bigint(slope2,twomulpx),params.p);
	bigint_t *pxsubx=sub_bigint(p.x,x);
	bigint_t *slopemulpxsubx=mul_bigint(slope,pxsubx);
	bigint_t *y=mod_bigint(sub_bigint(slopemulpxsubx,p.y),params.p);
	ecdsa_point_t result={x,y};
	return result;
}

ecdsa_point_t ecdsa_point_times(ecdsa_params_t params, bigint_t *times,ecdsa_point_t p)
{
	ecdsa_point_t result={.is_infinity=true};
	ecdsa_point_t current=p;
  for(int i=times->length-1; i>=0; i--){
		uint8_t byte=times->data[i];
		for(int j=0; j<8;j++) {
			bool is_bit_set=((byte>>j)&1);
			if(is_bit_set){
				result = ecdsa_point_add(params,result,current);
			}
			current = ecdsa_point_double(params,current);
		}
  }
	return result;
}

ecdsa_point_t ecdsa_point_add(ecdsa_params_t params, ecdsa_point_t p1, ecdsa_point_t p2)
{
  if(p1.is_infinity)
    return (ecdsa_point_t){p2.x,p2.y};
  if(p2.is_infinity)
    return (ecdsa_point_t){p1.x,p1.y};
  if(compare_bigint(p1.x,p2.x)==0 && compare_bigint(p1.y,p2.y)!=0)
    return (ecdsa_point_t){.is_infinity=true};
	bigint_t *ydiff=sub_bigint(p2.y,p1.y);
	bigint_t *xdiff=sub_bigint(p2.x,p1.x);
	bigint_t *modydiff=mod_bigint(ydiff,params.p);
	bigint_t *modxdiff=mod_bigint(xdiff,params.p);
	bigint_t *slope=mul_bigint(modydiff,mod_inverse(modxdiff,params.p));
	slope=mod_bigint(slope,params.p);
	bigint_t *slope2=mul_bigint(slope,slope);
	bigint_t *slopep1xdiff=sub_bigint(slope2,p1.x);
	bigint_t *slopep2xdiff=sub_bigint(slopep1xdiff,p2.x);
	bigint_t *x=mod_bigint(slopep2xdiff,params.p);
	bigint_t *p1xsubx=sub_bigint(p1.x,x);
	bigint_t *slopemulp1xsub=mul_bigint(slope,p1xsubx);
	bigint_t *slopemulsubp1y=sub_bigint(slopemulp1xsub,p1.y);
	bigint_t *y=mod_bigint(slopemulsubp1y,params.p);
	ecdsa_point_t result={x,y};
	return result;
}

bool ecdsa_signature_verify(ecdsa_params_t params, ecdsa_signature_t sig,bigint_t *z,ecdsa_point_t q)
{
	bigint_t *w = mod_inverse(sig.s,params.n);
	bigint_t *u1=mod_bigint(mul_bigint(z,w),params.n);
	bigint_t *u2=mod_bigint(mul_bigint(sig.r,w),params.n);
	ecdsa_point_t tmp1=ecdsa_point_times(params,u1,params.g);
	ecdsa_point_t tmp2=ecdsa_point_times(params,u2,q);
	ecdsa_point_t p=ecdsa_point_add(params,tmp1,tmp2);
	return compare_bigint(mod_bigint(p.x,params.n),sig.r)==0;
}
