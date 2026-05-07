#ifndef ECDSA_H
#define ECDSA_H

#include <stdbool.h>
#include "bigint.h"

typedef struct ecdsa_point_t {
	bigint_t *x;
	bigint_t *y;
  bool is_infinity;
} ecdsa_point_t;

typedef struct ecdsa_params_t {
	bigint_t *p;
	bigint_t *a;
	bigint_t *b;
	bigint_t *n;
  ecdsa_point_t g;
} ecdsa_params_t;


typedef struct ecdsa_signature_t {
	bigint_t *r;
	bigint_t *s;
} ecdsa_signature_t;

ecdsa_point_t ecdsa_point_add(ecdsa_params_t params, ecdsa_point_t p1, ecdsa_point_t p2);
//int ecdsa_mod(int num, unsigned int divisor);
//int ecdsa_gcd(int dividend, int divisor);
//xgcd_result_t ecdsa_xgcd(int a, int b);
//int ecdsa_mod_inverse(int num, unsigned int divisor);
ecdsa_point_t ecdsa_point_times(ecdsa_params_t params, bigint_t *times,ecdsa_point_t p);
bool ecdsa_signature_verify(
    ecdsa_params_t params, 
    ecdsa_signature_t sig,
    bigint_t *z,
    ecdsa_point_t q
    );

#endif
