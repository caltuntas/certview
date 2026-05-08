#include "test-framework/unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ecdsa.h"
#define ARRAY_LEN(arr) (sizeof(arr)/sizeof(arr[0]))
#define BIGINT(sign,...) (bigint_t){sign,(uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__})}

void setUp(void)
{
}

void tearDown(void)
{
}

typedef struct {
  ecdsa_point_t p;
  bigint_t *times;
  ecdsa_point_t result;
} test_case_ec_times;

static void test_times_point(void)
{
  bigint_t p=BIGINT(1,17);
  bigint_t a=BIGINT(1,2);
  bigint_t b=BIGINT(1,2);
  ecdsa_params_t params={
    .p=&p,
    .a=&a,
    .b=&b
  };
  test_case_ec_times cases[] = {
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(0),(ecdsa_point_t){.is_infinity=true}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(1),(ecdsa_point_t){create_bigint_from_int(5), create_bigint_from_int(1)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(2),(ecdsa_point_t){create_bigint_from_int(6), create_bigint_from_int(3)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(3),(ecdsa_point_t){create_bigint_from_int(10), create_bigint_from_int(6)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(4),(ecdsa_point_t){create_bigint_from_int(3), create_bigint_from_int(1)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(5),(ecdsa_point_t){create_bigint_from_int(9), create_bigint_from_int(16)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(6),(ecdsa_point_t){create_bigint_from_int(16), create_bigint_from_int(13)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(7),(ecdsa_point_t){create_bigint_from_int(0), create_bigint_from_int(6)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(8),(ecdsa_point_t){create_bigint_from_int(13), create_bigint_from_int(7)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(9),(ecdsa_point_t){create_bigint_from_int(7), create_bigint_from_int(6)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(10),(ecdsa_point_t){create_bigint_from_int(7), create_bigint_from_int(11)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(11),(ecdsa_point_t){create_bigint_from_int(13), create_bigint_from_int(10)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(12),(ecdsa_point_t){create_bigint_from_int(0), create_bigint_from_int(11)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(13),(ecdsa_point_t){create_bigint_from_int(16),create_bigint_from_int(4)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(14),(ecdsa_point_t){create_bigint_from_int(9),create_bigint_from_int(1)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(15),(ecdsa_point_t){create_bigint_from_int(3),create_bigint_from_int(16)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(16),(ecdsa_point_t){create_bigint_from_int(10),create_bigint_from_int(11)}},
    {(ecdsa_point_t){create_bigint_from_int(5),create_bigint_from_int(1)},create_bigint_from_int(19),(ecdsa_point_t){.is_infinity=true}},
  };
  size_t len = ARRAY_LEN(cases);
  for(int i=0; i<len; i++){
    test_case_ec_times tc=cases[i];
    ecdsa_point_t res=ecdsa_point_times(params,tc.times,tc.p);
    printf("case=%dP\n",i);
    if(tc.result.is_infinity){
      TEST_ASSERT_NULL(res.x);
      TEST_ASSERT_NULL(res.y);
      TEST_ASSERT_TRUE(res.is_infinity);
    } else {
      TEST_ASSERT_EQUAL_INT(tc.result.x->data[0],res.x->data[0]);
      TEST_ASSERT_EQUAL_INT(tc.result.y->data[0],res.y->data[0]);
    }
  }
}

static void test_add_point(void)
{
  bigint_t p=BIGINT(1,17);
  bigint_t a=BIGINT(1,2);
  bigint_t b=BIGINT(1,2);
  ecdsa_params_t params={
    .p=&p,
    .a=&a,
    .b=&b
  };
  ecdsa_point_t p1={create_bigint_from_int(5),create_bigint_from_int(1)};
  ecdsa_point_t p2={create_bigint_from_int(6),create_bigint_from_int(3)};
  ecdsa_point_t res=ecdsa_point_add(params,p1,p2);
  TEST_ASSERT_EQUAL_INT(10,res.x->data[0]);
  TEST_ASSERT_EQUAL_INT(6,res.y->data[0]);
  ecdsa_point_t p3={create_bigint_from_int(6),create_bigint_from_int(3)};
  ecdsa_point_t p4={create_bigint_from_int(3),create_bigint_from_int(1)};
  ecdsa_point_t res1=ecdsa_point_add(params,p3,p4);
  TEST_ASSERT_EQUAL_INT(16,res1.x->data[0]);
  TEST_ASSERT_EQUAL_INT(13,res1.y->data[0]);
  ecdsa_point_t p5={create_bigint_from_int(9),create_bigint_from_int(16)};
  ecdsa_point_t p6={create_bigint_from_int(5),create_bigint_from_int(16)};
  ecdsa_point_t res2=ecdsa_point_add(params,p5,p6);
  TEST_ASSERT_EQUAL_INT(3,res2.x->data[0]);
  TEST_ASSERT_EQUAL_INT(1,res2.y->data[0]);
}

static void test_times_and_add_consistency(void)
{
  bigint_t p=BIGINT(1,17);
  bigint_t a=BIGINT(1,2);
  bigint_t b=BIGINT(1,2);
  ecdsa_params_t params={
    .p=&p,
    .a=&a,
    .b=&b
  };
  ecdsa_point_t p1={create_bigint_from_int(5),create_bigint_from_int(1)};
  ecdsa_point_t p3 = ecdsa_point_times(params, create_bigint_from_int(3), p1);
  ecdsa_point_t p5 = ecdsa_point_times(params, create_bigint_from_int(5), p1);
  ecdsa_point_t p8 = ecdsa_point_times(params, create_bigint_from_int(8), p1);
  ecdsa_point_t sum = ecdsa_point_add(params, p3, p5);
  TEST_ASSERT_TRUE(compare_bigint(p8.x, sum.x)==0);
  TEST_ASSERT_TRUE(compare_bigint(p8.y, sum.y)==0);
}

static void test_signature_verify(void)
{
  ecdsa_params_t params={
    .p=create_bigint_from_int(17),
    .a=create_bigint_from_int(2),
    .b=create_bigint_from_int(2),
    .n=create_bigint_from_int(19),
    .g={create_bigint_from_int(5),create_bigint_from_int(1)},
  };
  bigint_t *z=create_bigint_from_int(11);
  ecdsa_signature_t sig={create_bigint_from_int(10),create_bigint_from_int(8)};
  ecdsa_point_t q={create_bigint_from_int(0),create_bigint_from_int(6)};
  bool valid=ecdsa_signature_verify(params,sig,z,q);
  TEST_ASSERT_TRUE(valid);
}

static void test_scalar_mul_identity(void)
{
  bigint_t p=BIGINT(1,17);
  bigint_t a=BIGINT(1,2);
  bigint_t b=BIGINT(1,2);
  ecdsa_params_t params={
    .p=&p,
    .a=&a,
    .b=&b
  };
  ecdsa_point_t p1 = {create_bigint_from_int(5), create_bigint_from_int(1)};
  ecdsa_point_t res = ecdsa_point_times(params, create_bigint_from_int(0), p1);
  TEST_ASSERT_TRUE(res.is_infinity);
}

static void test_addition_infinity(void)
{
  bigint_t p=BIGINT(1,17);
  bigint_t a=BIGINT(1,2);
  bigint_t b=BIGINT(1,2);
  ecdsa_params_t params={
    .p=&p,
    .a=&a,
    .b=&b
  };
  ecdsa_point_t p1 = {create_bigint_from_int(5), create_bigint_from_int(1)};
  ecdsa_point_t p3  = ecdsa_point_times(params, create_bigint_from_int(3), p1);
  ecdsa_point_t p16 = ecdsa_point_times(params, create_bigint_from_int(16), p1);
  ecdsa_point_t res = ecdsa_point_add(params, p16, p3);
  TEST_ASSERT_TRUE(res.is_infinity);
}

/*
 * Test vectors are extracted from a leaf and intermediate certificate download from example.com 
 * Curve: prime256v1 / secp256r1 / P-256
 *
 * Leaf certificate example1.der
 * Issuer (Intermediate certificate) cloudflare.der
 *
 * Signature algorithm: ecdsa-with-SHA256
 */
static void test_real_world_leaf_certificate_verify(void)
{
  bigint_t p = BIGINT(1,
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
  );

  bigint_t a = BIGINT(1,
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC
  );

  bigint_t b = BIGINT(1,
    0x5A,0xC6,0x35,0xD8,0xAA,0x3A,0x93,0xE7, 0xB3,0xEB,0xBD,0x55,0x76,0x98,0x86,0xBC, 0x65,0x1D,0x06,0xB0,0xCC,0x53,0xB0,0xF6, 0x3B,0xCE,0x3C,0x3E,0x27,0xD2,0x60,0x4B
  );

  bigint_t n = BIGINT(1,
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84, 0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51
  );

  ecdsa_params_t params = {
    .p = &p,
    .a = &a,
    .b = &b,
    .n = &n,

    .g = {
      &BIGINT(1,
        0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47, 0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2, 0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0, 0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96
      ),

      &BIGINT(1,
        0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B, 0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16, 0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE, 0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5
      )
    }
  };

   // Issuer public key extracted from cloudflare.der
  ecdsa_point_t issuer_q = {
    &BIGINT(1,
      0x07,0x21,0xC7,0x20,0x7C,0xAD,0x35,0x2C, 0xD3,0x4B,0xE1,0x77,0x24,0x0E,0xE1,0x1C, 0xC0,0xC6,0x77,0x67,0x29,0x71,0x8F,0x62, 0xDC,0xC2,0xD3,0x2A,0x61,0x3A,0x0C,0x94
    ),

    &BIGINT(1,
      0xCA,0x73,0xA2,0x70,0xBD,0x6E,0x74,0xA7, 0x02,0xA8,0x76,0xF7,0x76,0x42,0x3E,0x11, 0x00,0x0C,0xB6,0x8D,0x27,0xA3,0xB1,0x58, 0x30,0xE6,0x37,0xA1,0xEA,0xCC,0xAD,0xDC
    )
  };

   // Signature from example1.der
  ecdsa_signature_t sig = {
    &BIGINT(1,
      0x76,0x3C,0x5C,0x11,0xA6,0xF5,0x10,0xE9, 0xBD,0x49,0x03,0x9E,0x64,0xC0,0x0D,0xF7, 0xBF,0x20,0x9A,0xC3,0x57,0xFB,0xF0,0x28, 0x1E,0x68,0x34,0x42,0x9B,0xDB,0x1E,0x31
    ),

    &BIGINT(1,
      0x7C,0x39,0x2F,0x03,0x88,0x9D,0x87,0xEA, 0x97,0x3F,0xCC,0xA6,0xEB,0x75,0x7F,0xA0, 0x2D,0x4E,0x02,0xD7,0x90,0xEC,0x82,0x08, 0x7F,0xDA,0xFD,0xB1,0x4A,0x83,0xDD,0x20
    )
  };

  // SHA256(TBSCertificate) from example1.der
  bigint_t z = BIGINT(1,
    0x38,0xE6,0xDF,0xDC,0x8E,0xE5,0x86,0x90, 0xC6,0x68,0xEB,0x3F,0x63,0x69,0x3B,0x18, 0x29,0x75,0xD8,0x4C,0xCC,0xBF,0x02,0x64, 0x4F,0xF9,0x91,0x58,0x82,0x28,0x6C,0x19
  );

  bool valid =
    ecdsa_signature_verify(
      params,
      sig,
      &z,
      issuer_q
    );

  TEST_ASSERT_TRUE(valid);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_add_point);
  RUN_TEST(test_times_point);
  RUN_TEST(test_signature_verify);
  RUN_TEST(test_times_and_add_consistency);
  RUN_TEST(test_scalar_mul_identity);
  RUN_TEST(test_addition_infinity);
  RUN_TEST(test_real_world_leaf_certificate_verify);
  return UNITY_END();
}
