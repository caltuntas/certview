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

int ecdsa_mod_inverse(int num, unsigned int divisor) 
{
	int res=0,counter=0;
	while(res!=1) {
		res=(num * ++counter) % divisor;
	}
	return counter;
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
	ecdsa_point_t result=p;
	for(int i=0; i<times; i++){
		result = ecdsa_point_double(params,result);
	}
	return result;
}

ecdsa_point_t ecdsa_point_add(ecdsa_params_t params, ecdsa_point_t p1, ecdsa_point_t p2)
{
	int slope=ecdsa_mod(p2.y-p1.y,params.p)*ecdsa_mod_inverse(ecdsa_mod(p2.x-p1.x,params.p),params.p);
	slope=ecdsa_mod(slope,params.p);
	int x=ecdsa_mod(slope*slope-p1.x-p2.x,params.p);
	int y=ecdsa_mod(slope*(p1.x-x)-p1.y,params.p);
	ecdsa_point_t result={x,y};
	return result;
}
