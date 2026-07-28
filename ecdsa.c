#include <stdio.h>
#include "ecdsa.h"

ecdsa_params_t ecdsa_params[]= {
  //https://std.neuromancer.sk/x962/prime256v1
  [PRIME256V1]={
    .p = &BIGINT(1, 0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF),
    .a = &BIGINT(1, 0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC),
    .b = &BIGINT(1, 0x5A,0xC6,0x35,0xD8,0xAA,0x3A,0x93,0xE7, 0xB3,0xEB,0xBD,0x55,0x76,0x98,0x86,0xBC, 0x65,0x1D,0x06,0xB0,0xCC,0x53,0xB0,0xF6, 0x3B,0xCE,0x3C,0x3E,0x27,0xD2,0x60,0x4B),
    .n = &BIGINT(1, 0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84, 0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51),
    .g = {
      .x=&BIGINT(1,
        0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47, 0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2, 0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0, 0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96
      ),
      .y=&BIGINT(1,
        0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B, 0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16, 0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE, 0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5
      )
    }
  }
};


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
