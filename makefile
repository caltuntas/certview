CFLAGS = -g
all:
	gcc $(CFLAGS) main.c der.c -o certview

test:
	gcc -g test-framework/unity.c der.c test_der.c -o test_der.out
	./test_der.out

	gcc -g test-framework/unity.c der.c x509.c test_x509.c -o test_x509.out
	./test_x509.out

clean:
	rm -rf *.out *.o *.dSYM

.PHONY: test
