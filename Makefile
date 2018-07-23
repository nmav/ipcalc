USE_GEOIP?=no
USE_MAXMIND?=yes
USE_RUNTIME_LINKING?=yes

LIBPATH?=/usr/lib64
#LIBPATH=/usr/lib/x86_64-linux-gnu

LIBS?=
VERSION=0.2.4
CC?=gcc
CFLAGS?=-O2 -g -Wall
LDFLAGS=$(LIBS)

ifeq ($(USE_GEOIP),yes)
ifeq ($(USE_RUNTIME_LINKING),yes)
LDFLAGS+=-ldl
CFLAGS+=-DUSE_GEOIP -DUSE_RUNTIME_LINKING -DLIBPATH="\"$(LIBPATH)\""
else
LDFLAGS+=-lGeoIP
CFLAGS+=-DUSE_GEOIP
endif # DYN GEOIP
else  # GEOIP
ifeq ($(USE_MAXMIND),yes)
ifeq ($(USE_RUNTIME_LINKING),yes)
LDFLAGS+=-ldl
CFLAGS+=-DUSE_MAXMIND -DUSE_RUNTIME_LINKING -DLIBPATH="\"$(LIBPATH)\""
else
LDFLAGS+=-lmaxminddb
CFLAGS+=-DUSE_MAXMIND
endif # DYN MAXMIND
endif # MAXMIND
endif # not GEOIP

all: ipcalc

ipcalc: ipcalc.c ipcalc-geoip.c ipcalc-maxmind.c ipcalc-reverse.c ipcalc-utils.c netsplit.c
	$(CC) $(CFLAGS) -DVERSION="\"$(VERSION)\"" $^ -o $@ $(LDFLAGS)

clean:
	rm -f ipcalc

SPLIT_LINES="$(shell ./ipcalc -S 29 192.168.5.0/24 | grep ^Network | wc -l)"
SPLIT_TOTAL="$(shell ./ipcalc -S 29 192.168.5.0/24|grep ^Total|cut -d ':' -f 2|tr -d '[:space:]')"
SPLIT_LINES_IPV6="$(shell ./ipcalc -S 120 fcfa:b4ca:f1d8:125b:dc00::/112 | grep ^Network | wc -l)"
SPLIT_TOTAL_IPV6="$(shell ./ipcalc -S 120 fcfa:b4ca:f1d8:125b:dc00::/112|grep ^Total|cut -d ':' -f 2|tr -d '[:space:]')"

check: ipcalc
	./ipcalc -bmnp 12.15.1.5 --class-prefix > out.tmp && cmp out.tmp tests/12.15.1.5
	./ipcalc -bmnp 129.15.31.5 --class-prefix > out.tmp && cmp out.tmp tests/129.15.31.5
	./ipcalc -bmnp 193.92.31.0 --class-prefix > out.tmp && cmp out.tmp tests/193.92.31.0
	./ipcalc -bmnp 192.168.1.5/31 > out.tmp && cmp out.tmp tests/192.168.1.5-31
	./ipcalc -bmnp 10.10.10.5/24 > out.tmp && cmp out.tmp tests/192.168.1.5-24
	./ipcalc -bmnp 10.100.4.1/30 > out.tmp && cmp out.tmp tests/192.168.1.5-30
	./ipcalc -bmnp 10.100.4.1/16 > out.tmp && cmp out.tmp tests/192.168.1.5-16
	./ipcalc -bmnp 10.10.10.10/8 > out.tmp && cmp out.tmp tests/192.168.1.5-8
	./ipcalc -S 18 10.10.10.10/16 > out.tmp && cmp out.tmp tests/split-10.10.10.0-16-18
	./ipcalc -S 24 10.10.10.0/16 > out.tmp && cmp out.tmp tests/split-10.10.10.0-16-24
	./ipcalc -S 26 192.168.5.45/24 > out.tmp && cmp out.tmp tests/split-192.168.5.45-24-26
	./ipcalc -S 29 192.168.5.0/24 > out.tmp && cmp out.tmp tests/split-192.168.5.0-24-29
	./ipcalc -S 31 192.168.5.0/24 > out.tmp && cmp out.tmp tests/split-192.168.5.0-24-31
	./ipcalc -S 32 192.168.5.0/24 > out.tmp && cmp out.tmp tests/split-192.168.5.0-24-32
	./ipcalc -S 64 2a03:2880:20:4f06:face::/56 > out.tmp && cmp out.tmp tests/split-2a03:2880:20:4f06:face::-56-64
	./ipcalc -S 128 fcfa:b4ca:f1d8:125b:dc00::/127 > out.tmp && cmp out.tmp tests/split-fcfa:b4ca:f1d8:125b:dc00::-127-128
	./ipcalc -S 120 fcfa:b4ca:f1d8:125b:dc00::/112 > out.tmp && cmp out.tmp tests/split-fcfa:b4ca:f1d8:125b:dc00::-112-120
	./ipcalc --no-decorate -S 18 10.10.10.10/16 > out.tmp && cmp out.tmp tests/nsplit-10.10.10.0-16-18
	./ipcalc --no-decorate -S 24 10.10.10.0/16 > out.tmp && cmp out.tmp tests/nsplit-10.10.10.0-16-24
	./ipcalc --no-decorate -S 26 192.168.5.45/24 > out.tmp && cmp out.tmp tests/nsplit-192.168.5.45-24-26
	./ipcalc --no-decorate -S 29 192.168.5.0/24 > out.tmp && cmp out.tmp tests/nsplit-192.168.5.0-24-29
	./ipcalc --no-decorate -S 31 192.168.5.0/24 > out.tmp && cmp out.tmp tests/nsplit-192.168.5.0-24-31
	./ipcalc --no-decorate -S 32 192.168.5.0/24 > out.tmp && cmp out.tmp tests/nsplit-192.168.5.0-24-32
	./ipcalc --no-decorate -S 64 2a03:2880:20:4f06:face::/56 > out.tmp && cmp out.tmp tests/nsplit-2a03:2880:20:4f06:face::-56-64
	./ipcalc --no-decorate -S 128 fcfa:b4ca:f1d8:125b:dc00::/127 > out.tmp && cmp out.tmp tests/nsplit-fcfa:b4ca:f1d8:125b:dc00::-127-128
	./ipcalc --no-decorate -S 120 fcfa:b4ca:f1d8:125b:dc00::/112 > out.tmp && cmp out.tmp tests/nsplit-fcfa:b4ca:f1d8:125b:dc00::-112-120
	./ipcalc --addrspace -bmnp 193.92.150.3/24 > out.tmp && cmp out.tmp tests/193.92.150.3-24
	./ipcalc --addrspace -bmnp fd95:6be5:0ae0:84a5::/64 > out.tmp && cmp out.tmp tests/fd95:6be5:0ae0:84a5::-64
	./ipcalc --addrspace -bmnp fd0b:a336:4e7d::/48 > out.tmp && cmp out.tmp tests/fd0b:a336:4e7d::-48
	./ipcalc -i 2a03:2880:20:4f06:face:b00c:0:1 > out.tmp && cmp out.tmp tests/i-2a03:2880:20:4f06:face:b00c:0:1
	./ipcalc -i fd0b:a336:4e7d::/48 > out.tmp && cmp out.tmp tests/i-fd0b:a336:4e7d::-48
	test "$(SPLIT_LINES_IPV6)" = "$(SPLIT_TOTAL_IPV6)"
	test "$(SPLIT_LINES)" = "$(SPLIT_TOTAL)"
	./ipcalc-tests

