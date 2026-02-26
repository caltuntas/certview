#ifndef BIGINT_H
#define BIGINT_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
  NEGATIVE=-1,
  NON_NEGATIVE=1
} sign_t;

typedef struct bigint_t {
	sign_t sign;
	uint8_t *data;
	size_t length;
} bigint_t;

void bigint_ltrim(bigint_t *bi,uint8_t val);
bigint_t *create_bigint(uint8_t *buf,size_t len);
bigint_t *mul_bigint(bigint_t *num1, bigint_t *num2);
bigint_t *add_bigint(bigint_t *num1, bigint_t *num2);
bigint_t *sub_bigint(bigint_t *num1, bigint_t *num2);
bigint_t *bigint_from_decimal_str(char *decimal);
char *bigint_to_decimal_str(bigint_t *num);
int compare_bigint(bigint_t *num1, bigint_t *num2);
char *mul(char *x, char *y,int base);
char *add(char *x, char *y,int base);
char *sub(char *x, char *y);
char *hex_to_decimal_str(uint8_t *hex,size_t len);
int compare(char *x, char *y);

#endif
