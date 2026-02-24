#ifndef ECDSA_H
#define ECDSA_H

#include <stdbool.h>

typedef struct ecdsa_params_t {
	int p;
	int a;
	int b;
	int n;
	int z;
} ecdsa_params_t;

typedef struct ecdsa_point_t {
	int x;
	int y;
} ecdsa_point_t;

int ecdsa_mod(int num, unsigned int divisor);
int ecdsa_mod_inverse(int num, unsigned int divisor);
ecdsa_point_t ecdsa_point_times(ecdsa_params_t params, int times,ecdsa_point_t p);
ecdsa_point_t ecdsa_point_add(ecdsa_params_t params, ecdsa_point_t p1, ecdsa_point_t p2);
bool ecdsa_verify(ecdsa_params_t params, ecdsa_point_t p1,ecdsa_point_t g,ecdsa_point_t q);

#endif
