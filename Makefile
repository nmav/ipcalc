CC=gcc
CFLAGS=-O2 -g

all: ipcalc

ipcalc: ipcalc.c
	$(CC) $(CFLAGS) $^ -o $@ -lpopt
