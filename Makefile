CC=gcc
CFLAGS=-O2 -g -Wall

all: ipcalc

ipcalc: ipcalc.c
	$(CC) $(CFLAGS) $^ -o $@ -lpopt

clean:
	rm -f ipcalc

check: ipcalc
	./ipcalc -bmnp 192.168.1.5/31 > out.tmp && cmp out.tmp tests/192.168.1.5-31
	./ipcalc -bmnp 10.10.10.5/24 > out.tmp && cmp out.tmp tests/192.168.1.5-24
	./ipcalc -bmnp 10.100.4.1/30 > out.tmp && cmp out.tmp tests/192.168.1.5-30
	./ipcalc -bmnp 10.100.4.1/16 > out.tmp && cmp out.tmp tests/192.168.1.5-16
	./ipcalc -bmnp 10.10.10.10/8 > out.tmp && cmp out.tmp tests/192.168.1.5-8
	./ipcalc -bmnp fd95:6be5:0ae0:84a5::/64 > out.tmp && cmp out.tmp tests/fd95:6be5:0ae0:84a5::-64
	./ipcalc -bmnp fd0b:a336:4e7d::/48 > out.tmp && cmp out.tmp tests/fd0b:a336:4e7d::-48
