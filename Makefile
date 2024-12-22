CC=gcc
CFLAGS=-Wall -Wextra
SRC=main.c

all: project

project: $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)
