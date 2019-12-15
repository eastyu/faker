faker:faker.c
	gcc -g -Wall -std=c99 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -o faker faker.c -lpthread -lssl -lcrypto
.PHONY:clean
clean:
	rm -rf faker
