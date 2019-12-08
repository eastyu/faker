faker:faker.c
	gcc -Wall -std=c99 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -o faker faker.c -lpthread
.PHONY:clean
clean:
	rm -rf faker
