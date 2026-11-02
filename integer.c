#include <limits.h>
#include <stddef.h>
#include "integer.h"


bool integer_add_int_safe(int a, int b, int *out)
{
  if(out==NULL)
    return false;
  //Overflow if only a+b>INT_MAX, in other words b>INT_MAX-a
  //But INT_MAX-a is only safely computable when a>0;
  //if a<0 it would itself overflow, and in that case
  //b>INT_MAX-a can never hold anyway, so we skip it.

  //Underflow if only a+b<INT_MIN, in other words b<INT_MIN-a
  //INT_MIN-a is only safely computable when a<0
  if((a>0 && b>INT_MAX-a) ||(a<0 && b<INT_MIN-a))
    return false;
  *out=a+b;
  return true;
}
