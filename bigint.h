#ifndef BIGINT_H
#define BIGINT_H

#include <stdint.h>
#include <stddef.h>

#define BIGINT(sign,...) (bigint_t){sign,(uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__})}

typedef enum {
  NEGATIVE=-1,
  NON_NEGATIVE=1
} sign_t;

typedef struct bigint_t {
	sign_t sign;
	uint8_t *data;
	size_t length;
} bigint_t;

typedef struct xgcd_result_t {
  bigint_t *g;
	bigint_t *x;
	bigint_t *y;
} xgcd_result_t;

void bigint_ltrim(bigint_t *bi,uint8_t val);
bigint_t *create_bigint(uint8_t *buf,size_t len);
bigint_t *create_bigint_from_int(int num);
bigint_t *mul_bigint(bigint_t *num1, bigint_t *num2);
bigint_t *add_bigint(bigint_t *num1, bigint_t *num2);
bigint_t *sub_bigint(bigint_t *num1, bigint_t *num2);
bigint_t *div_bigint(bigint_t *num1, bigint_t *num2, bigint_t **remainder);
bigint_t *shift_left_bigint(bigint_t *num1,int bits);
bigint_t *shift_right_bigint(bigint_t *num1,int bits);
bigint_t *mod_bigint(bigint_t *num1, bigint_t *num2);
bigint_t *bigint_from_decimal_str(char *decimal);
bigint_t *gcd_bigint(bigint_t *dividend, bigint_t *divisor) ;
xgcd_result_t xgcd_bigint(bigint_t *dividend, bigint_t *divisor) ;
bigint_t *mod_inverse(bigint_t *num, bigint_t *divisor) ;
char *bigint_to_decimal_str(bigint_t *num);
int compare_bigint(bigint_t *num1, bigint_t *num2);
int bigint_convert_to_int(bigint_t *num);
#endif
