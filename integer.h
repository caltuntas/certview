#ifndef INTEGER_H
#define INTEGER_H

#include <stdbool.h>

bool integer_add_int_safe(int a, int b, int *out);
bool integer_add_sizet_safe(size_t a, size_t b, size_t *out);

#endif
