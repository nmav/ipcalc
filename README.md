[![Build Status](https://travis-ci.org/nmav/ipcalc.svg?branch=master)](https://travis-ci.org/nmav/ipcalc)

Information about this ipcalc
=============================

This is a modern ipcalc tool for IPv4 and IPv6. It acts both as a tool
to output human readable information about a network or address, as well
as a tool suitable to be used by scripts or other programs.

It supports printing a summary about the provided network address, multiple
command line options per information to be printed, transparent IPv6 support,
and in addition it will use libGeoIP if available to provide geographic information.


Examples
========

## IPv4

```
$ ./ipcalc --all-info 193.92.150.2/24
Address:	193.92.150.2
Network:	193.92.150.0/24
Address space:	Internet
Address class:	Class C
Netmask:	255.255.255.0 = 24
Broadcast:	193.92.150.255

HostMin:	193.92.150.1
HostMax:	193.92.150.254
Hosts/Net:	254

Country code:	GR
Country:	Greece
```

```
$ ./ipcalc -pnmb --minaddr --maxaddr --geoinfo --addrspace 193.92.150.2/255.255.255.224
NETMASK=255.255.255.224
PREFIX=27
BROADCAST=193.92.150.31
NETWORK=193.92.150.0
MINADDR=193.92.150.1
MAXADDR=193.92.150.30
ADDRSPACE="Internet"
COUNTRY="Greece"
```

## IPv6

```
$ ./ipcalc --all-info 2a03:2880:20:4f06:face:b00c:0:14/64
Full Address:	2a03:2880:0020:4f06:face:b00c:0000:0014
Address:	2a03:2880:20:4f06:face:b00c:0:14
Full Network:	2a03:2880:0020:4f06:0000:0000:0000:0000
Network:	2a03:2880:20:4f06::/64
Address space:	Global Unicast
Netmask:	ffff:ffff:ffff:ffff:: = 64

HostMin:	2a03:2880:20:4f06::
HostMax:	2a03:2880:20:4f06:ffff:ffff:ffff:ffff
Hosts/Net:	2^(64) = 18446744073709551616

Country code:	IE
Country:	Ireland
```

```
$ ./ipcalc -pnmb --minaddr --maxaddr --addrspace --geoinfo 2a03:2880:20:4f06:face:b00c:0:14/64
NETMASK=ffff:ffff:ffff:ffff::
PREFIX=64
NETWORK=2a03:2880:20:4f06::
MINADDR=2a03:2880:20:4f06::
MAXADDR=2a03:2880:20:4f06:ffff:ffff:ffff:ffff
ADDRSPACE="Global Unicast"
COUNTRY="Ireland"
```
