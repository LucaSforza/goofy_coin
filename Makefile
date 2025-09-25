all: main

CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lssl -lcrypto

main: main.c
	$(CC) $(CFLAGS) -ggdb main.c ssl_digital_signature.c -o main $(LIBS)
