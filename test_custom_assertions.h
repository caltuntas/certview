#ifndef TEST_CUSTOM_ASSERTIONS
#define  TEST_CUSTOM_ASSERTIONS

#include "test-framework/unity.h"
#include "bigint.h"

void AssertBigIntEqual(const bigint_t *expected, const bigint_t *actual, UNITY_LINE_TYPE line);

#define TEST_ASSERT_BIGINT_EQUAL(expected,actual) \
  AssertBigIntEqual((expected),(actual),__LINE__)

#endif

