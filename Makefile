faker:faker.c
	gcc -Wall -std=c99 -D_POSIX_C_SOURCE=200809L -o faker faker.c
.PHONY:clean
clean:
	rm -rf faker
