# Makefile
CC = g++
CFLAGS = -Wall -std=c++11 -lssl -lcrypto

all: main

main: main.cpp
	$(CC) $(CFLAGS) -o main main.cpp

clean:
	rm -f main rmdfound.txt