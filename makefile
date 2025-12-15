CFLAGS = -g
all:
	gcc $(CFLAGS) main.c der.c -o certview

test:
	gcc -g test-framework/unity.c der.c test_der.c -o test_der.out
	./test_der.out

clean:
	rm -rf *.out *.o *.dSYM

.PHONY: test
