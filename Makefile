all: main

CC = gcc
CFLAGS = -Wall -Wextra -pedantic -ggdb 
LIBS = -lssl -lcrypto -lreadline -lm

ssl_digital_signature.o: src/ssl_digital_signature.c
	$(CC) $(CFLAGS) -c src/ssl_digital_signature.c -o ssl_digital_signature.o $(LIBS)

strings_utils.o: src/strings_utils.c
	$(CC) $(CFLAGS) -c src/strings_utils.c -o strings_utils.o	

main.o: src/main.c 
	$(CC) $(CFLAGS) -c src/main.c -o main.o

main: main.o ssl_digital_signature.o strings_utils.o
	$(CC) $(CFLAGS) strings_utils.o ssl_digital_signature.o main.o -o main $(LIBS)
