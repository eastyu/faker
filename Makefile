faker:faker.c
	gcc -Wall -std=c99 -D_POSIX_C_SOURCE -o faker faker.c
.PHONY:clean
clean:
	rm -rf faker
