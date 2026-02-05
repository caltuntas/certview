CFLAGS = -g
all:
	gcc $(CFLAGS) main.c der.c x509.c -o certview

test:
	gcc -g test-framework/unity.c der.c test_der.c -o test_der.out
	./test_der.out

	gcc -g test-framework/unity.c der.c x509.c bigint.c oid.c test_x509.c -o test_x509.out
	./test_x509.out

	gcc -g test-framework/unity.c bigint.c test_bigint.c -o test_bigint.out
	./test_bigint.out

	gcc -g test-framework/unity.c der.c x509.c bigint.c oid.c test_decode.c -o test_decode.out
	./test_decode.out

	gcc -g test-framework/unity.c oid.c test_oid.c -o test_oid.out
	./test_oid.out

clean:
	rm -rf *.out *.o *.dSYM

.PHONY: test
