CFLAGS = -g
all:
	gcc $(CFLAGS) main.c der.c asn1.c oid.c bigint.c -o certview

test:
	gcc -g test-framework/unity.c der.c test_der.c -o test_der.out
	./test_der.out

	gcc -g test-framework/unity.c ecdsa.c bigint.c test_ecdsa.c -o test_ecdsa.out
	./test_ecdsa.out

	gcc -g test-framework/unity.c der.c asn1.c bigint.c oid.c test_asn1.c -o test_asn1.out
	./test_asn1.out

	gcc -g test-framework/unity.c bigint.c test_bigint.c -o test_bigint.out
	./test_bigint.out

	gcc -g test-framework/unity.c der.c asn1.c bigint.c oid.c test_decode.c -o test_decode.out
	./test_decode.out

	gcc -g test-framework/unity.c oid.c test_oid.c -o test_oid.out
	./test_oid.out

clean:
	rm -rf *.out *.o *.dSYM

.PHONY: test
