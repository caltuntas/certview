#!/usr/bin/env bash
set -euo pipefail
#set -x

CERT="$1"

if [ ! -f "$CERT" ]; then
  echo "Usage: $0 <cert.der>"
  exit 1
fi

echo "== Curve =="
openssl x509 -in "$CERT" -inform DER -text -noout | grep "ASN1 OID"

echo
echo "== Extract Public Key (Qx, Qy) =="

PUB_HEX=$(openssl x509 -in "$CERT" -inform DER -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | tail -c 65 | xxd -p -c 65)

# remove leading 04
PUB_HEX=${PUB_HEX:2}

QX=${PUB_HEX:0:64}
QY=${PUB_HEX:64:64}

echo "Qx = $QX"
echo "Qy = $QY"

echo
echo "== Extract Signature (r, s) =="

SIG_OFFSET=$(openssl asn1parse -in "$CERT" -inform DER | grep "BIT STRING" | tail -1 |tr -d ' '| cut -d: -f1)

RS=$(openssl asn1parse -in "$CERT" -inform DER -strparse "$SIG_OFFSET" | tail +2 | awk -F':' '{print $4}')

R=$(echo "$RS" | head -1)
S=$(echo "$RS" | tail -1)

echo "r = $R"
echo "s = $S"

echo
echo "== Extract TBS and compute z =="

openssl asn1parse -inform DER -in $CERT -out tbs.bin -noout -strparse 4

Z=$(openssl dgst -sha256 tbs.bin | awk '{print $NF}')
rm tbs.bin

echo "z = $Z"

echo
echo "== Done =="
