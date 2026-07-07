#include "test_custom_assertions.h"

void AssertBigIntEqual(const bigint_t *expected, const bigint_t *actual, UNITY_LINE_TYPE line)
{
  if (expected->sign != actual->sign){
    UnityFail("BigInt sign mismatch", line);
  }

  if (expected->length != actual->length){
    UnityFail("BigInt length mismatch", line);
  }

  UnityAssertEqualIntArray(
      (UNITY_INTERNAL_PTR)expected->data,
      (UNITY_INTERNAL_PTR)actual->data,
      (UNITY_UINT32)expected->length,
      "BigInt data mismatch",
      line,
      UNITY_DISPLAY_STYLE_UINT8,
      UNITY_ARRAY_TO_ARRAY);
}

