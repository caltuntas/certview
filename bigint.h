#ifndef BIGINT_H
#define BIGINT_H

#include <stdint.h>
#include <stddef.h>

typedef struct bigint_t {
	short sign;
	uint8_t *data;
	size_t length;
} bigint_t;

bigint_t *create_bigint(uint8_t *buf,size_t len);
char *bigint_to_decimal_str(bigint_t *bigint);
char *mul(char *x, char *y);
char *add(char *x, char *y);
char *sub(char *x, char *y);
char *hex_to_decimal_str(uint8_t *hex,size_t len);
int compare(char *x, char *y);

#endif
