/*
 * Copyright (c) 1997-2015 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *   Nikos Mavrogiannopoulos <nmav@redhat.com>
 *   Erik Troan <ewt@redhat.com>
 *   Preston Brown <pbrown@redhat.com>
 *   David Cantrell <dcantrell@redhat.com>
 */

#define _GNU_SOURCE		/* asprintf */
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>		/* open */
#include <fcntl.h>		/* open */
#include <unistd.h>		/* read */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>		/* clock_gettime */
#include <limits.h>
#include <error.h>

#include "ipcalc.h"

/*!
  \file ipcalc.c
  \brief provides utilities for manipulating IP addresses.

  ipcalc provides utilities and a front-end command line interface for
  manipulating IP addresses, and calculating various aspects of an ip
  address/netmask/network address/prefix/etc.

  Functionality can be accessed from other languages from the library
  interface, documented here.  To use ipcalc from the shell, read the
  ipcalc(1) manual page.

  When passing parameters to the various functions, take note of whether they
  take host byte order or network byte order.  Most take host byte order, and
  return host byte order, but there are some exceptions.
*/

static int safe_atoi(const char *s, int *ret_i)
{
	char *x = NULL;
	long l;

	errno = 0;
	l = strtol(s, &x, 0);

	if (!x || x == s || *x || errno)
		return errno > 0 ? -errno : -EINVAL;

	if ((long)(int)l != l)
		return -ERANGE;

	*ret_i = (int)l;
	return 0;
}

/*!
  \fn char safe_strdup(const char *s)
  \brief strdup(3) that checks memory allocation or fail

  This function does the same as strdup(3) with additional memory allocation
  check.  When check fails the function will cause program to exit.

  \param string to be duplicated
  \return allocated duplicate
*/
extern char __attribute__((warn_unused_result)) *safe_strdup(const char *str)
{
	char *ret;

	if (!str)
		return NULL;

	ret = strdup(str);
	if (!ret) {
		error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__, "memory allocation failure");
	}
	return ret;
}

extern int __attribute__((__format__(printf, 2, 3)))
safe_asprintf(char **strp, const char *fmt, ...)
{
	int ret;
	va_list args;

	va_start(args, fmt);
	ret = vasprintf(&(*strp), fmt, args);
	va_end(args);
	if (ret < 0) {
		error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__, "memory allocation failure");
	}
	return ret;
}



/*!
  \fn uint32_t prefix2mask(int bits)
  \brief creates a netmask from a specified number of bits

  This function converts a prefix length to a netmask.  As CIDR (classless
  internet domain internet domain routing) has taken off, more an more IP
  addresses are being specified in the format address/prefix
  (i.e. 192.168.2.3/24, with a corresponding netmask 255.255.255.0).  If you
  need to see what netmask corresponds to the prefix part of the address, this
  is the function.  See also \ref mask2prefix.

  \param prefix is the number of bits to create a mask for.
  \return a network mask, in network byte order.
*/
uint32_t prefix2mask(int prefix)
{
	if (prefix) {
		return htonl(~((1 << (32 - prefix)) - 1));
	} else {
		return htonl(0);
	}
}

/*!
  \fn struct in_addr calc_broadcast(struct in_addr addr, int prefix)

  \brief calculate broadcast address given an IP address and a prefix length.

  \param addr an IP address in network byte order.
  \param prefix a prefix length.

  \return the calculated broadcast address for the network, in network byte
  order.
*/
static struct in_addr calc_broadcast(struct in_addr addr, int prefix)
{
	struct in_addr mask;
	struct in_addr broadcast;

	mask.s_addr = prefix2mask(prefix);

	memset(&broadcast, 0, sizeof(broadcast));
	broadcast.s_addr = (addr.s_addr & mask.s_addr) | ~mask.s_addr;
	return broadcast;
}

/*!
  \fn struct in_addr calc_network(struct in_addr addr, int prefix)
  \brief calculates the network address for a specified address and prefix.

  \param addr an IP address, in network byte order
  \param prefix the network prefix
  \return the base address of the network that addr is associated with, in
  network byte order.
*/
static struct in_addr calc_network(struct in_addr addr, int prefix)
{
	struct in_addr mask;
	struct in_addr network;

	mask.s_addr = prefix2mask(prefix);

	memset(&network, 0, sizeof(network));
	network.s_addr = addr.s_addr & mask.s_addr;
	return network;
}

/*!
  \fn const char *get_hostname(const struct ipcalc_control *ctl, void *addr, const char *ipStr)
  \brief returns the hostname associated with the specified IP address

  \param ctl contains the address family, either AF_INET or AF_INET6.
  \param addr an IP address to find a hostname for, in network byte order,
  should either be a pointer to a struct in_addr or a struct in6_addr.

  \return a hostname, or NULL if one cannot be determined.  Hostname is stored
  in an allocated buffer.
*/
static char *get_hostname(const struct ipcalc_control *ctl, void *addr, const char *ipStr)
{
	static char hostname[NI_MAXHOST];
	int ret = -1;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;

	if (ctl->family == AF_INET) {
		memset(&addr4, 0, sizeof(addr4));
		addr4.sin_family = AF_INET;
		memcpy(&addr4.sin_addr, addr, sizeof(struct in_addr));
		ret = getnameinfo((struct sockaddr*)&addr4, sizeof(addr4), hostname, sizeof(hostname), NULL, 0, 0);
	} else if (ctl->family == AF_INET6) {
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		memcpy(&addr6.sin6_addr, addr, sizeof(struct in6_addr));
		ret = getnameinfo((struct sockaddr*)&addr6, sizeof(addr6), hostname, sizeof(hostname), NULL, 0, 0);
	}

	if (ret != 0) {
		if (!ctl->beSilent) {
			error(0, 0, "cannot find hostname for %s: %s", ipStr, gai_strerror(ret));
		}
		return NULL;
	}

	return safe_strdup(hostname);
}

/*!
  \fn const char *get_ip_address(const struct ipcalc_control *ctl)
  \brief returns the IP address associated with the specified hostname

  \param family the requested address family or AF_UNSPEC for any
  \param host a hostname

  \return an IP address, or NULL if one cannot be determined.  The IP is stored
  in an allocated buffer.
*/
static char *get_ip_address(const struct ipcalc_control *ctl)
{
	struct addrinfo *res, *rp;
	struct addrinfo hints;
	int err;
	static char ipname[64];
	void *addr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ctl->family;

	err = getaddrinfo(ctl->hostname, NULL, &hints, &res);
	if (err != 0)
		return NULL;

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET)
			addr = (&((struct sockaddr_in *)(rp->ai_addr))->sin_addr);
		else
			addr = (&((struct sockaddr_in6 *)(rp->ai_addr))->sin6_addr);

		if (inet_ntop(rp->ai_family, addr, ipname, sizeof(ipname)) != NULL) {
			freeaddrinfo(res);
			return safe_strdup(ipname);
		}
	}

	freeaddrinfo(res);
	return NULL;
}

static int bit_count(uint32_t i)
{
	int c = 0;
	unsigned int seen_one = 0;

	while (i > 0) {
		if (i & 1) {
			seen_one = 1;
			c++;
		} else {
			if (seen_one) {
				return -1;
			}
		}
		i >>= 1;
	}

	return c;
}

/*!
  \fn int mask2prefix(struct in_addr mask)
  \brief calculates the number of bits masked off by a netmask.

  This function calculates the significant bits in an IP address as specified by
  a netmask.  See also \ref prefix2mask.

  \param mask is the netmask, specified as an struct in_addr in network byte order.
  \return the number of significant bits.  */
static int mask2prefix(struct in_addr mask)
{
	return bit_count(ntohl(mask.s_addr));
}

static
int ipv4_mask_to_int(const char *prefix)
{
	int ret;
	struct in_addr in;

	ret = inet_pton(AF_INET, prefix, &in);
	if (ret == 0)
		return -1;

	return mask2prefix(in);
}

/* Returns powers of two in textual format */
static const char *p2_table(unsigned pow)
{
	static const char *pow2[] = {
		"1",
		"2",
		"4",
		"8",
		"16",
		"32",
		"64",
		"128",
		"256",
		"512",
		"1024",
		"2048",
		"4096",
		"8192",
		"16384",
		"32768",
		"65536",
		"131072",
		"262144",
		"524288",
		"1048576",
		"2097152",
		"4194304",
		"8388608",
		"16777216",
		"33554432",
		"67108864",
		"134217728",
		"268435456",
		"536870912",
		"1073741824",
		"2147483648",
		"4294967296",
		"8589934592",
		"17179869184",
		"34359738368",
		"68719476736",
		"137438953472",
		"274877906944",
		"549755813888",
		"1099511627776",
		"2199023255552",
		"4398046511104",
		"8796093022208",
		"17592186044416",
		"35184372088832",
		"70368744177664",
		"140737488355328",
		"281474976710656",
		"562949953421312",
		"1125899906842624",
		"2251799813685248",
		"4503599627370496",
		"9007199254740992",
		"18014398509481984",
		"36028797018963968",
		"72057594037927936",
		"144115188075855872",
		"288230376151711744",
		"576460752303423488",
		"1152921504606846976",
		"2305843009213693952",
		"4611686018427387904",
		"9223372036854775808",
		"18446744073709551616",
		"36893488147419103232",
		"73786976294838206464",
		"147573952589676412928",
		"295147905179352825856",
		"590295810358705651712",
		"1180591620717411303424",
		"2361183241434822606848",
		"4722366482869645213696",
		"9444732965739290427392",
		"18889465931478580854784",
		"37778931862957161709568",
		"75557863725914323419136",
		"151115727451828646838272",
		"302231454903657293676544",
		"604462909807314587353088",
		"1208925819614629174706176",
		"2417851639229258349412352",
		"4835703278458516698824704",
		"9671406556917033397649408",
		"19342813113834066795298816",
		"38685626227668133590597632",
		"77371252455336267181195264",
		"154742504910672534362390528",
		"309485009821345068724781056",
		"618970019642690137449562112",
		"1237940039285380274899124224",
		"2475880078570760549798248448",
		"4951760157141521099596496896",
		"9903520314283042199192993792",
		"19807040628566084398385987584",
		"39614081257132168796771975168",
		"79228162514264337593543950336",
		"158456325028528675187087900672",
		"316912650057057350374175801344",
		"633825300114114700748351602688",
		"1267650600228229401496703205376",
		"2535301200456458802993406410752",
		"5070602400912917605986812821504",
		"10141204801825835211973625643008",
		"20282409603651670423947251286016",
		"40564819207303340847894502572032",
		"81129638414606681695789005144064",
		"162259276829213363391578010288128",
		"324518553658426726783156020576256",
		"649037107316853453566312041152512",
		"1298074214633706907132624082305024",
		"2596148429267413814265248164610048",
		"5192296858534827628530496329220096",
		"10384593717069655257060992658440192",
		"20769187434139310514121985316880384",
		"41538374868278621028243970633760768",
		"83076749736557242056487941267521536",
		"166153499473114484112975882535043072",
		"332306998946228968225951765070086144",
		"664613997892457936451903530140172288",
		"1329227995784915872903807060280344576",
		"2658455991569831745807614120560689152",
		"5316911983139663491615228241121378304",
		"10633823966279326983230456482242756608",
		"21267647932558653966460912964485513216",
		"42535295865117307932921825928971026432",
		"85070591730234615865843651857942052864",
		"170141183460469231731687303715884105728",
	};
	if (pow <= 127)
		return pow2[pow];
	return "";
}

static const char *ipv4_net_to_type(struct in_addr net)
{
	unsigned byte1 = (ntohl(net.s_addr) >> 24) & 0xff;
	unsigned byte2 = (ntohl(net.s_addr) >> 16) & 0xff;
	unsigned byte3 = (ntohl(net.s_addr) >> 8) & 0xff;
	unsigned byte4 = (ntohl(net.s_addr)) & 0xff;

	/* based on IANA's iana-ipv4-special-registry and ipv4-address-space
	 * Updated: 2015-05-12
	 */
	if (byte1 == 0) {
		return "This host on this network";
	}

	if (byte1 == 10) {
		return "Private Use";
	}

	if (byte1 == 100 && (byte2 & 0xc0) == 64) {
		return "Shared Address Space";
	}

	if (byte1 == 127) {
		return "Loopback";
	}

	if (byte1 == 169 && byte2 == 254) {
		return "Link Local";
	}

	if (byte1 == 172 && (byte2 & 0xf0) == 16) {
		return "Private Use";
	}

	if (byte1 == 192 && byte2 == 0 && byte3 == 0) {
		return "IETF Protocol Assignments";
	}

	if (byte1 == 192 && byte2 == 2 && byte3 == 0) {
		return "Documentation (TEST-NET-1)";
	}

	if (byte1 == 192 && byte2 == 51 && byte3 == 100) {
		return "Documentation (TEST-NET-2)";
	}

	if (byte1 == 203 && byte2 == 0 && byte3 == 113) {
		return "Documentation (TEST-NET-3)";
	}

	if (byte1 == 192 && byte2 == 88 && byte3 == 99) {
		return "6 to 4 Relay Anycast (Deprecated)";
	}

	if (byte1 == 192 && byte2 == 52 && byte3 == 193) {
		return "AMT";
	}

	if (byte1 == 192 && byte2 == 168) {
		return "Private Use";
	}

	if (byte1 == 255 && byte2 == 255 && byte3 == 255 && byte4 == 255) {
		return "Limited Broadcast";
	}

	if (byte1 == 198 && (byte2 & 0xfe) == 18) {
		return "Benchmarking";
	}

	if (byte1 >= 224 && byte1 <= 239) {
		return "Multicast";
	}

	if ((byte1 & 0xf0) == 240) {
		return "Reserved";
	}

	return "Internet";
}

static
const char *ipv4_net_to_class(struct in_addr net)
{
	unsigned byte1 = (ntohl(net.s_addr) >> 24) & 0xff;

	if (byte1 < 128) {
		return "Class A";
	}

	if (byte1 >= 128 && byte1 < 192) {
		return "Class B";
	}

	if (byte1 >= 192 && byte1 < 224) {
		return "Class C";
	}

	if (byte1 >= 224 && byte1 < 239) {
		return "Class D";
	}

	return "Class E";
}

static
unsigned default_ipv4_prefix(struct in_addr net)
{
	unsigned byte1 = (ntohl(net.s_addr) >> 24) & 0xff;

	if (byte1 < 128) {
		return 8;
	}

	if (byte1 >= 128 && byte1 < 192) {
		return 16;
	}

	if (byte1 >= 192 && byte1 < 224) {
		return 24;
	}

	return 24;
}

char *ipv4_prefix_to_hosts(char *hosts, unsigned hosts_size, unsigned prefix)
{
	unsigned tmp;

	if (prefix >= 31) {
		snprintf(hosts, hosts_size, "%s", p2_table(32 - prefix));
	} else {
		tmp = (1 << (32 - prefix)) - 2;
		snprintf(hosts, hosts_size, "%u", tmp);
	}
	return hosts;
}

char *ipv6_prefix_to_hosts(char *hosts, unsigned hosts_size, unsigned prefix)
{
	snprintf(hosts, hosts_size, "%s", p2_table(128 - prefix));
	return hosts;
}

static
int get_ipv4_info(struct ipcalc_control *ctl, char *ipStr, int prefix,
		  ip_info_st *info)
{
	struct in_addr ip, netmask, network, broadcast, minhost, maxhost;
	char namebuf[INET_ADDRSTRLEN + 1];

	memset(info, 0, sizeof(*info));

	if (inet_pton(AF_INET, ipStr, &ip) <= 0) {
		if (!ctl->beSilent)
			error(0, 0, "bad IPv4 address: %s",
				ipStr);
		return -1;
	}

	/* Handle CIDR entries such as 172/8 */
	if (prefix >= 0) {
		char *tmp = (char *)ipStr;
		int i;

		for (i = 3; i > 0; i--) {
			tmp = strchr(tmp, '.');
			if (!tmp)
				break;
			else
				tmp++;
		}

		tmp = NULL;
		for (; i > 0; i--) {
			if (safe_asprintf(&tmp, "%s.0", ipStr) == -1) {
				error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__,
					"memory allocation failure");
			}
			ipStr = tmp;
		}
	} else { /* assume good old days classful Internet */
		if (ctl->assume_class_prefix)
			prefix = default_ipv4_prefix(ip);
		else
			prefix = 32;
	}

	if (prefix > 32) {
		if (!ctl->beSilent)
			error(0, 0, "bad IPv4 prefix: %d", prefix);
		return -1;
	}

	if (inet_ntop(AF_INET, &ip, namebuf, sizeof(namebuf)) == 0) {
		if (!ctl->beSilent)
			error(0, 0, "error calculating the IPv4 network");
		return -1;
	}
	info->ip = safe_strdup(namebuf);

	netmask.s_addr = prefix2mask(prefix);
	memset(namebuf, '\0', sizeof(namebuf));

	if (inet_ntop(AF_INET, &netmask, namebuf, INET_ADDRSTRLEN) == NULL) {
		error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__,
			"memory allocation failure");
	}
	info->netmask = safe_strdup(namebuf);
	info->prefix = prefix;

	broadcast = calc_broadcast(ip, prefix);

	memset(namebuf, '\0', sizeof(namebuf));
	if (inet_ntop(AF_INET, &broadcast, namebuf, INET_ADDRSTRLEN) == NULL) {
		error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__,
			"memory allocation failure");
	}
	info->broadcast = safe_strdup(namebuf);

	network = calc_network(ip, prefix);

	info->reverse_dns = calc_reverse_dns4(network, prefix, network, broadcast);

	memset(namebuf, '\0', sizeof(namebuf));
	if (inet_ntop(AF_INET, &network, namebuf, INET_ADDRSTRLEN) == NULL) {
		error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__,
			"memory allocation failure");
	}

	info->network = safe_strdup(namebuf);

	info->type = ipv4_net_to_type(network);
	info->class = ipv4_net_to_class(network);

	if (prefix < 32) {
		memcpy(&minhost, &network, sizeof(minhost));

		if (prefix <= 30)
			minhost.s_addr = htonl(ntohl(minhost.s_addr) | 1);
		if (inet_ntop(AF_INET, &minhost, namebuf, INET_ADDRSTRLEN) ==
		    NULL) {
			error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__,
				"memory allocation failure");
		}
		info->hostmin = safe_strdup(namebuf);

		memcpy(&maxhost, &network, sizeof(minhost));
		maxhost.s_addr |= ~netmask.s_addr;
		if (prefix <= 30) {
			maxhost.s_addr = htonl(ntohl(maxhost.s_addr) - 1);
		}
		if (inet_ntop(AF_INET, &maxhost, namebuf, sizeof(namebuf)) == 0) {
			if (!ctl->beSilent)
				error(0, 0, "error calculating the IPv4 network");
			return -1;
		}

		info->hostmax = safe_strdup(namebuf);
	} else {
		info->hostmin = info->network;
		info->hostmax = info->network;
	}

	ipv4_prefix_to_hosts(info->hosts, sizeof(info->hosts), prefix);

#ifdef USE_GEOIP
	if (ctl->get_geoip) {
		geo_ipv4_lookup(ctl, ip, &info->geoip_country, &info->geoip_ccode, &info->geoip_city, &info->geoip_coord);
	}
#endif

	if (ctl->resolve_host) {
		info->hostname = get_hostname(ctl, &ip, ipStr);
		if (info->hostname == NULL) {
			return -1;
		}
	}

	return 0;
}

int ipv6_prefix_to_mask(unsigned prefix, struct in6_addr *mask)
{
	struct in6_addr in6;
	int i, j;

	if (prefix > 128)
		return -1;

	memset(&in6, 0x0, sizeof(in6));
	for (i = prefix, j = 0; i > 0; i -= 8, j++) {
		if (i >= 8) {
			in6.s6_addr[j] = 0xff;
		} else {
			in6.s6_addr[j] = (unsigned long)(0xffU << (8 - i));
		}
	}

	memcpy(mask, &in6, sizeof(*mask));
	return 0;
}

static char *ipv6_mask_to_str(const struct in6_addr *mask)
{
	char buf[128];

	if (inet_ntop(AF_INET6, mask, buf, sizeof(buf)) == NULL)
		return NULL;

	return safe_strdup(buf);
}

static const char *ipv6_net_to_type(struct in6_addr *net, int prefix)
{
	uint16_t word1 = net->s6_addr[0] << 8 | net->s6_addr[1];
	uint16_t word2 = net->s6_addr[2] << 8 | net->s6_addr[3];

	/* based on IANA's iana-ipv6-special-registry and ipv6-address-space 
	 * Updated: 2015-05-12
	 */
	if (prefix == 128 && memcmp
	    (net->s6_addr,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
	     16) == 0)
		return "Loopback Address";

	if (prefix == 128 && memcmp
	    (net->s6_addr,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	     16) == 0)
		return "Unspecified Address";

	if (prefix >= 96 && memcmp
	    (net->s6_addr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff",
	     12) == 0)
		return "IPv4-mapped Address";

	if (prefix >= 96 && memcmp
	    (net->s6_addr, "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00",
	     12) == 0)
		return "IPv4-IPv6 Translat.";

	if (prefix >= 96 && memcmp
	    (net->s6_addr, "\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	     12) == 0)
		return "Discard-Only Address Block";

	if ((word1 & 0xfffe) == 0x2001 && word2 == 0)
		return "IETF Protocol Assignments";

	if ((word1 & 0xe000) == 0x2000) {
		return "Global Unicast";
	}

	if (((net->s6_addr[0] & 0xfe) == 0xfc)) {
		return "Unique Local Unicast";
	}

	if ((word1 & 0xffc0) == 0xfe80) {
		return "Link-Scoped Unicast";
	}

	if ((net->s6_addr[0] & 0xff) == 0xff) {
		return "Multicast";
	}

	if ((word1 & 0xfffe) == 0x2002)
		return "6to4";

	return "Reserved";
}

static
char *expand_ipv6(struct in6_addr *ip6)
{
	char buf[128];
	char *p;
	unsigned i;

	p = buf;
	for (i = 0; i < 16; i++) {
		sprintf(p, "%.2x", (unsigned)ip6->s6_addr[i]);
		p += 2;
		if (i % 2 != 0 && i != 15) {
			*p = ':';
			p++;
		}
	}
	*p = 0;

	return safe_strdup(buf);
}

static
int get_ipv6_info(struct ipcalc_control *ctl, const char *ipStr,
		  int prefix, ip_info_st *info)
{
	struct in6_addr ip6, mask, network;
	char errBuf[250];
	unsigned i;

	memset(info, 0, sizeof(*info));

	if (inet_pton(AF_INET6, ipStr, &ip6) <= 0) {
		if (!ctl->beSilent)
			error(0, 0, "bad IPv6 address: %s", ipStr);
		return -1;
	}

	/* expand  */
	info->expanded_ip = expand_ipv6(&ip6);

	if (inet_ntop(AF_INET6, &ip6, errBuf, sizeof(errBuf)) == 0) {
		if (!ctl->beSilent)
			error(0, 0, "error calculating the IPv6 network");
		return -1;
	}

	info->ip = safe_strdup(errBuf);

	if (prefix > 128) {
		if (!ctl->beSilent)
			error(0, 0, "bad IPv6 prefix: %d", prefix);
		return -1;
	} else if (prefix < 0) {
		prefix = 128;
	}

	info->prefix = prefix;

	if (ipv6_prefix_to_mask(prefix, &mask) == -1) {
		if (!ctl->beSilent)
			error(0, 0, "error converting IPv6 prefix: %d", prefix);
		return -1;
	}

	info->netmask = ipv6_mask_to_str(&mask);

	for (i = 0; i < sizeof(struct in6_addr); i++)
		network.s6_addr[i] = ip6.s6_addr[i] & mask.s6_addr[i];

	if (inet_ntop(AF_INET6, &network, errBuf, sizeof(errBuf)) == 0) {
		if (!ctl->beSilent)
			error(0, 0, "error calculating the IPv6 network");
		return -1;
	}

	info->network = safe_strdup(errBuf);

	info->expanded_network = expand_ipv6(&network);
	info->type = ipv6_net_to_type(&network, prefix);

	info->reverse_dns = calc_reverse_dns6(&network, prefix);

	if (prefix < 128) {
		info->hostmin = safe_strdup(errBuf);

		for (i = 0; i < sizeof(struct in6_addr); i++)
			network.s6_addr[i] |= ~mask.s6_addr[i];
		if (inet_ntop(AF_INET6, &network, errBuf, sizeof(errBuf)) == 0) {
			if (!ctl->beSilent)
				error(0, 0, "error calculating the IPv6 network");
			return -1;
		}

		info->hostmax = safe_strdup(errBuf);
	} else {
		info->hostmin = info->network;
		info->hostmax = info->network;
	}

	ipv6_prefix_to_hosts(info->hosts, sizeof(info->hosts), prefix);

#ifdef USE_GEOIP
	if (ctl->get_geoip) {
		geo_ipv6_lookup(ctl, &ip6, &info->geoip_country, &info->geoip_ccode, &info->geoip_city, &info->geoip_coord);
	}
#endif

	if (ctl->resolve_host) {
		info->hostname = get_hostname(ctl, &ip6, ipStr);
		if (info->hostname == NULL) {
			return -1;
		}
	}
	return 0;
}

static int randomize(void *ptr, ssize_t size)
{
	int fd;
	ssize_t ret;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, ptr, size);
	close(fd);

	if (ret != size) {
		return -1;
	}

	return 0;
}

static char *generate_ip_network(const struct ipcalc_control *ctl, unsigned prefix)
{
	struct timespec ts;
	char ipbuf[64];
	char *p = NULL;

	if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) < 0)
		return NULL;

	if (ctl->family == AF_INET6) {
		struct in6_addr net;

		net.s6_addr[0] = 0xfc;
		net.s6_addr[0] |= ts.tv_nsec & 1;
		if (randomize(&net.s6_addr[1], 15) < 0)
			return NULL;

		if (inet_ntop(AF_INET6, &net, ipbuf, sizeof(ipbuf)) == NULL)
			return NULL;
	} else {
		struct in_addr net;
		unsigned c = ts.tv_nsec % 4;
		uint8_t bytes[4];

		if (randomize(bytes, 4) < 0)
			return NULL;

		if (prefix >= 16 && c < 2) {
			if (c == 1) {
				bytes[0] = 192;
				bytes[1] = 168;
			} else {
				bytes[0] = 172;
				bytes[1] = 16 | ((ts.tv_nsec >> 4) & 0x0f);
			}
		} else {
			bytes[0] = 10;
		}

		memcpy(&net.s_addr, bytes, 4);

		if (inet_ntop(AF_INET, &net, ipbuf, sizeof(ipbuf)) == NULL)
			return NULL;
	}

	if (safe_asprintf(&p, "%s/%u", ipbuf, prefix) == -1)
		return NULL;

	return p;
}

static
int str_to_prefix(struct ipcalc_control *ctl, const char *prefixStr, unsigned fix)
{
	int prefix = -1, r;
	if (ctl->family == AF_INET && strchr(prefixStr, '.')) {	/* prefix is 255.x.x.x */
		prefix = ipv4_mask_to_int(prefixStr);
	} else {
		r = safe_atoi(prefixStr, &prefix);
		if (r != 0) {
			return -1;
		}
	}

	if (fix && (prefix > 32))
		ctl->family = AF_INET6;

	if (prefix < 0 || ((ctl->family == AF_INET && prefix > 32) || prefix > 128)) {
		return -1;
	}
	return prefix;
}

static
void usage(unsigned verbose)
{
	if (verbose) {
		fprintf(stderr, "Usage: ipcalc [OPTION...]\n");
		fprintf(stderr, "  -c, --check                     Validate IP address\n");
		fprintf(stderr, "  -r, --random-private=PREFIX     Generate a random private IP network using\n");
		fprintf(stderr, "  -S, --split=PREFIX              Split the provided network using the\n");
		fprintf(stderr, "                                  provided prefix/netmask\n");
		fprintf(stderr, "  -i, --info                      Print information on the provided IP address\n");
		fprintf(stderr, "      --all-info                  Print verbose information on the provided IP\n");
		fprintf(stderr, "                                  address\n");
		fprintf(stderr, "      --reverse-dns               Print network in a the reverse DNS format\n");
		fprintf(stderr, "  -4, --ipv4                      Explicitly specify the IPv4 address family\n");
		fprintf(stderr, "  -6, --ipv6                      Explicitly specify the IPv6 address family\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "Specific info options:\n");
		fprintf(stderr, "  -b, --broadcast                 Display calculated broadcast address\n");
		fprintf(stderr, "  -m, --netmask                   Display netmask for IP\n");
		fprintf(stderr, "  -n, --network                   Display network address\n");
		fprintf(stderr, "  -p, --prefix                    Display network prefix\n");
		fprintf(stderr, "      --minaddr                   Display the minimum address in the network\n");
		fprintf(stderr, "      --maxaddr                   Display the maximum address in the network\n");
		fprintf(stderr, "      --addresses                 Display the maximum number of addresses in\n");
		fprintf(stderr, "                                  the network\n");
		fprintf(stderr, "      --addrspace                 Display the address space the network\n");
		fprintf(stderr, "                                  resides on\n");
		fprintf(stderr, "  -h, --hostname                  Show hostname determined via DNS\n");
		fprintf(stderr, "  -o, --lookup-host=STRING        Show IP as determined via DNS\n");
#ifdef USE_GEOIP
		fprintf(stderr, "  -g, --geoinfo                   Show Geographic information about the\n");
		fprintf(stderr, "                                  provided IP\n");
#endif
		fprintf(stderr, "\n");
		fprintf(stderr, "Other options:\n");
		fprintf(stderr, "      --class-prefix              When specified the default prefix will be determined\n");
		fprintf(stderr, "                                  by the IPv4 address class\n");
		fprintf(stderr, "  -s, --silent                    Don't ever display error messages\n");
		fprintf(stderr, "  -v, --version                   Display program version\n");
		fprintf(stderr, "  -?, --help                      Show this help message\n");
		fprintf(stderr, "      --usage                     Display brief usage message\n");
	} else {
		fprintf(stderr, "Usage: ipcalc [-46sv?] [-c|--check] [-r|--random-private=STRING] [-i|--info]\n");
		fprintf(stderr, "        [--all-info] [-4|--ipv4] [-6|--ipv6] [-b|--broadcast]\n");
		fprintf(stderr, "        [-h|--hostname] [-o|--lookup-host=STRING]");
#ifdef USE_GEOIP
		fprintf(stderr, " [-g|--geoinfo]\n");
#else
		fprintf(stderr, "\n");
#endif
		fprintf(stderr, "        [-m|--netmask] [-n|--network] [-p|--prefix] [--minaddr] [--maxaddr]\n");
		fprintf(stderr, "        [--addresses] [--addrspace] [-s|--silent] [-v|--version]\n");
		fprintf(stderr, "        [--reverse-dns] [--class-prefix]\n");
		fprintf(stderr, "        [-?|--help] [--usage]\n");
	}
}

void
__attribute__ ((format(printf, 4, 5)))
color_printf(const struct ipcalc_control *ctl, const char *color, const char *title, const char *fmt, ...)
{
	va_list args;
	int ret;
	char *str = NULL;

	va_start(args, fmt);
	ret = vasprintf(&str, fmt, args);
	va_end(args);

	if (ret < 0)
		return;

	fputs(title, stdout);
	if (ctl->colors)
		fputs(color, stdout);

	fputs(str, stdout);
	if (ctl->colors)
		fputs(KRESET, stdout);
	free(str);
	return;
}

static void parse_args(struct ipcalc_control *ctl, int argc, char **argv)
{
	int c;
	enum {
		OPT_ALLINFO = CHAR_MAX + 1,
		OPT_REVERSE,
		OPT_CLASS_PREFIX,
		OPT_MINADDR,
		OPT_MAXADDR,
		OPT_ADDRESSES,
		OPT_ADDRSPACE,
		OPT_USAGE
	};
	static const struct option long_options[] = {
		{ "check",		no_argument,		NULL, 'c'		},
		{ "random-private",	required_argument,	NULL, 'r'		},
		{ "split",		required_argument,	NULL, 'S'		},
		{ "info",		no_argument,		NULL, 'i'		},
		{ "all-info",		no_argument,		NULL, OPT_ALLINFO	},
		{ "ipv4",		no_argument,		NULL, '4'		},
		{ "ipv6",		no_argument,		NULL, '6'		},
		{ "broadcast",		no_argument,		NULL, 'b'		},
		{ "hostname",		no_argument,		NULL, 'h'		},
		{ "lookup-host",	required_argument,	NULL, 'o'		},
		{ "reverse-dns",	no_argument,		NULL, OPT_REVERSE	},
#ifdef USE_GEOIP
		{ "geoinfo",		no_argument,		NULL, 'g'		},
#endif
		{ "netmask",		no_argument,		NULL, 'm'		},
		{ "network",		no_argument,		NULL, 'n'		},
		{ "prefix",		no_argument,		NULL, 'p'		},
		{ "class-prefix",	no_argument,		NULL, OPT_CLASS_PREFIX	},
		{ "minaddr",		no_argument,		NULL, OPT_MINADDR	},
		{ "maxaddr",		no_argument,		NULL, OPT_MAXADDR	},
		{ "addresses",		no_argument,		NULL, OPT_ADDRESSES	},
		{ "addrspace",		no_argument,		NULL, OPT_ADDRSPACE	},
		{ "silent",		no_argument,		NULL, 's'		},
		{ "version",		no_argument,		NULL, 'v'		},
		{ "help",		no_argument,		NULL, '?'		},
		{ "usage",		no_argument,		NULL, OPT_USAGE		},
		{ NULL, 0, NULL, 0 }
	};
	while (1) {
		c = getopt_long(argc, argv, "S:cr:i46bho:gmnpsv", long_options, NULL);
		if (c == -1)
			break;

		switch(c) {
			case 'c':
				ctl->check_address = 1;
			break;
			case 'S':
				ctl->split = 1;
				ctl->splitStr = safe_strdup(optarg);
				break;
			case 'r':
				ctl->randomStr = safe_strdup(optarg);
				break;
			case OPT_ALLINFO:
				ctl->show_all = 1;
				/* fallthrough */
			case 'i':
				ctl->show_info = 1;
				break;
			case OPT_CLASS_PREFIX:
				ctl->assume_class_prefix = 1;
				break;
			case OPT_REVERSE:
				ctl->show_reverse = 1;
				break;
			case '4':
			case '6':
				if (ctl->family != AF_UNSPEC && !ctl->beSilent) {
					error(EXIT_FAILURE, 0, "you cannot specify both IPv4 and IPv6");
				}
				if (c == '4')
					ctl->family = AF_INET;
				else
					ctl->family = AF_INET6;
				break;
			case 'b':
				ctl->show_broadcast = 1;
				break;
			case 'h':
				ctl->resolve_host = 1;
				break;
			case 'o':
				ctl->hostname = safe_strdup(optarg);
				break;
#ifdef USE_GEOIP
			case 'g':
				ctl->get_geoip = 1;
				ctl->show_geoip = 1;
				break;
#endif
			case 'm':
				ctl->show_netmask = 1;
				break;
			case 'n':
				ctl->show_network = 1;
				break;
			case 'p':
				ctl->show_prefix = 1;
				break;
			case OPT_MINADDR:
				ctl->show_min_addr = 1;
				break;
			case OPT_MAXADDR:
				ctl->show_max_addr = 1;
				break;
			case OPT_ADDRESSES:
				ctl->show_addresses = 1;
				break;
			case OPT_ADDRSPACE:
				ctl->show_address_space = 1;
				break;
			case 's':
				ctl->beSilent = 1;
				break;
			case 'v':
				printf("ipcalc %s\n", VERSION);
				exit(EXIT_SUCCESS);
				break;
			case OPT_USAGE:
				usage(0);
				exit(EXIT_SUCCESS);
			case '?':
			default:
				usage(1);
				exit(EXIT_SUCCESS);
		}
	}
	return;
}

static int option_not_specified(const struct ipcalc_control *ctl)
{
	if (ctl->resolve_host ||
	    ctl->revolve_ip ||
	    ctl->check_address ||
	    ctl->show_info ||
	    ctl->show_broadcast ||
	    ctl->show_netmask ||
	    ctl->show_network ||
	    ctl->show_prefix ||
	    ctl->show_min_addr ||
	    ctl->show_max_addr ||
	    ctl->show_addresses ||
	    ctl->show_address_space ||
#ifdef USE_GEOIP
	    ctl->show_geoip ||
#endif
	    ctl->show_all ||
	    ctl->show_reverse)
		return 0;
	return 1;
}

static int close_stream(FILE *stream)
{
	const int some_pending = (__fpending(stream) != 0);
	const int prev_fail = (ferror(stream) != 0);
	const int fclose_fail = (fclose(stream) != 0);

	if (prev_fail || (fclose_fail && (some_pending || errno != EBADF))) {
		if (!fclose_fail && !(errno == EPIPE))
			errno = 0;
		return EOF;
	}
	return 0;
}

/* Meant to be used atexit(close_stdout); */
static void close_stdout(void)
{
	if (close_stream(stdout) != 0 && !(errno == EPIPE))
		error(EXIT_FAILURE, errno, "stdout write error");
	if (close_stream(stderr) != 0 && !(errno == EPIPE))
		error(EXIT_FAILURE, errno, "stderr write error");
}

/*!
  \fn main(int argc, const char **argv)
  \brief wrapper program for ipcalc functions.

  This is a wrapper program for the functions that the ipcalc library provides.
  It can be used from shell scripts or directly from the command line.

  For more information, please see the ipcalc(1) man page.
*/
int main(int argc, char **argv)
{
	struct ipcalc_control ctl = { .family = AF_UNSPEC,  0 };
	int doCheck = 0;
	char *ipStr = NULL, *prefixStr = NULL, *netmaskStr = NULL, *chptr = NULL;
	int prefix = -1, splitPrefix = -1;
	ip_info_st info = { 0 };
	int r = 0;

	atexit(close_stdout);
	parse_args(&ctl, argc, argv);
	if (optind < argc) {
		ipStr = argv[optind++];
		if (optind < argc)
			chptr = argv[optind++];
	}

	if (ctl.hostname)
		ctl.revolve_ip = 1;

#ifdef USE_GEOIP
	if (ctl.show_all && geo_setup(&ctl) == 0)
		ctl.get_geoip = 1;
#endif

	if ((ctl.hostname && ctl.randomStr) ||
	    (ctl.hostname && ctl.splitStr) ||
	    (ctl.randomStr && ctl.splitStr)) {
		if (!ctl.beSilent)
			error(EXIT_FAILURE, 0, "--lookup-host --random-private and --split options cannot be mixed");
		return 1;
	}

	if (ctl.hostname == NULL && ctl.randomStr == NULL && !ipStr) {
		if (!ctl.beSilent) {
			error(EXIT_FAILURE, 0, "ip address expected");
		}
		return 1;
	}

	/* resolve IP address if a hostname was given */
	if (ctl.hostname) {
		ipStr = get_ip_address(&ctl);
		if (ipStr == NULL) {
			if (!ctl.beSilent)
				error(EXIT_FAILURE, 0, "could not resolve %s", ctl.hostname);
			return 1;
		}
	} else if (ctl.randomStr) { /* generate a random private network if asked */
		prefix = str_to_prefix(&ctl, ctl.randomStr, 1);
		if (prefix < 0) {
			if (!ctl.beSilent)
				error(EXIT_FAILURE, 0, "bad %s prefix: %s",
					ctl.family == AF_INET6 ? "IPv6" : "IPv4", ctl.randomStr);
			return 1;
		}

		ipStr = generate_ip_network(&ctl, prefix);
		if (ipStr == NULL) {
			if (!ctl.beSilent)
				error(EXIT_FAILURE, 0, "cannot generate network with prefix: %u",
					prefix);
			return 1;
		}
	} else if (ctl.splitStr) {
		splitPrefix = str_to_prefix(&ctl, ctl.splitStr, 1);
		if (splitPrefix < 0) {
			if (!ctl.beSilent)
				error(EXIT_FAILURE, 0, "bad %s prefix: %s",
					ctl.family == AF_INET6 ? "IPv6" : "IPv4", ctl.splitStr);
			return 1;
		}
	}

	/* if there is a : in the address, it is an IPv6 address.
	 * Note that we allow -4, and -6 to be given explicitly, so
	 * that the tool can be used to check for a valid IPv4 or IPv6
	 * address.
	 */
	if (ctl.family == AF_UNSPEC) {
		if (strchr(ipStr, ':') != NULL) {
			ctl.family = AF_INET6;
		} else if (ctl.family == AF_UNSPEC) {
			ctl.family = AF_INET;
		}
	}

	if (chptr) {
		if (ctl.family == AF_INET) {
			prefixStr = chptr;
		} else {
			if (!ctl.beSilent) {
				error(EXIT_FAILURE, 0, "unexpected argument: %s",
					chptr);
			}
			return 1;
		}
	}

	if (prefixStr == NULL && strchr(ipStr, '/') != NULL) {
		prefixStr = strchr(ipStr, '/');
		*prefixStr = '\0';	/* fix up ipStr */
		prefixStr++;
	}

	if (prefixStr != NULL) {
		prefix = str_to_prefix(&ctl, prefixStr, 0);
		if (prefix < 0) {
			if (!ctl.beSilent)
				error(EXIT_FAILURE, 0, "bad %s prefix: %s",
					ctl.family == AF_INET6 ? "IPv6" : "IPv4", prefixStr);
			return 1;
		}
	}

	if (ctl.family == AF_INET6) {
		r = get_ipv6_info(&ctl, ipStr, prefix, &info);
	} else {
		if (ctl.show_broadcast || ctl.show_network || ctl.show_prefix) {
			if (netmaskStr && prefix >= 0) {
				if (!ctl.beSilent) {
					error(EXIT_FAILURE, 0, "both netmask and prefix specified");
				}
				return 1;
			}
		}

		if (prefix == -1 && netmaskStr) {
			prefix = ipv4_mask_to_int(netmaskStr);
			if (prefix < 0) {
				if (!ctl.beSilent)
					error(EXIT_FAILURE, 0, "bad IPv4 prefix: %s", prefixStr);
				return 1;
			}
		}
		r = get_ipv4_info(&ctl, ipStr, prefix, &info);
	}

	if (r < 0) {
		return 1;
	}

	if (doCheck)
		return 0;

	/* if no option is given, print information on IP */
	if (option_not_specified(&ctl)) {
		ctl.show_info = 1;
	}

	if (isatty(STDOUT_FILENO) != 0)
		ctl.colors = 1;

	/* we know what we want to display now, so display it. */
	if (ctl.show_info && !ctl.split) {
		unsigned single_host = 0;

		if ((ctl.family == AF_INET6 && info.prefix == 128) ||
		    (ctl.family == AF_INET && info.prefix == 32)) {
			single_host = 1;
		}

		if ((!ctl.randomStr || single_host) &&
		    (single_host || strcmp(info.network, info.ip) != 0)) {
			if (info.expanded_ip)
				color_printf(&ctl, KBLUE, "Full Address:\t", "%s\n", info.expanded_ip);
			color_printf(&ctl, KBLUE, "Address:\t", "%s\n", info.ip);
		}

		if (!single_host) {
			if (info.expanded_network) {
				color_printf(&ctl, KBLUE, "Full Network:\t", "%s/%u\n", info.expanded_network, info.prefix);
			}

			color_printf(&ctl, KBLUE, "Network:\t", "%s/%u\n", info.network, info.prefix);

			color_printf(&ctl, KBLUE, "Netmask:\t", "%s = %u\n", info.netmask, info.prefix);


			if (info.broadcast)
				color_printf(&ctl, KBLUE, "Broadcast:\t", "%s\n", info.broadcast);
		}

		if (ctl.show_all && info.reverse_dns)
			color_printf(&ctl, KBLUE, "Reverse DNS:\t", "%s\n", info.reverse_dns);

		if (!single_host) {
			printf("\n");
			if (info.type)
				color_printf(&ctl, KMAG, "Address space:\t", "%s\n", info.type);
			if (info.class)
				color_printf(&ctl, KMAG, "Address class:\t", "%s\n", info.class);

			if (info.hostmin)
				color_printf(&ctl, KBLUE, "HostMin:\t", "%s\n", info.hostmin);

			if (info.hostmax)
				color_printf(&ctl, KBLUE, "HostMax:\t", "%s\n", info.hostmax);

			if (ctl.family == AF_INET6 && info.prefix < 112)
				color_printf(&ctl, KBLUE, "Hosts/Net:\t", "2^(%u) = %s\n", 128-info.prefix, info.hosts);
			else
				color_printf(&ctl, KBLUE, "Hosts/Net:\t", "%s\n", info.hosts);
		} else {
			if (info.type)
				color_printf(&ctl, KMAG, "Address space:\t", "%s\n", info.type);
			if (info.class)
				color_printf(&ctl, KMAG, "Address class:\t", "%s\n", info.class);

		}

		if (info.geoip_country || info.geoip_city || info.geoip_coord) {
			printf("\n");
			if (info.geoip_ccode)
				color_printf(&ctl, KMAG, "Country code:\t", "%s\n", info.geoip_ccode);
			if (info.geoip_country)
				color_printf(&ctl, KMAG, "Country:\t", "%s\n", info.geoip_country);
			if (info.geoip_city)
				color_printf(&ctl, KMAG, "City:\t\t", "%s\n", info.geoip_city);
			if (info.geoip_coord)
				color_printf(&ctl, KMAG, "Coordinates:\t", "%s\n", info.geoip_coord);
		}

	} else if (!ctl.show_info) {

		if (ctl.show_netmask) {
			printf("NETMASK=%s\n", info.netmask);
		}

		if (ctl.show_prefix) {
			printf("PREFIX=%u\n", info.prefix);
		}

		if (ctl.show_broadcast && ctl.family == AF_INET) {
			printf("BROADCAST=%s\n", info.broadcast);
		}

		if (ctl.show_network) {
			printf("NETWORK=%s\n", info.network);
		}

		if (ctl.show_reverse) {
			printf("REVERSEDNS=%s\n", info.reverse_dns);
		}

		if (ctl.show_min_addr && info.hostmin) {
			printf("MINADDR=%s\n", info.hostmin);
		}

		if (ctl.show_max_addr && info.hostmax) {
			printf("MAXADDR=%s\n", info.hostmax);
		}

		if (ctl.show_address_space && info.type) {
			if (strchr(info.type, ' ') != NULL)
				printf("ADDRSPACE=\"%s\"\n", info.type);
			else
				printf("ADDRSPACE=%s\n", info.type);
		}

		if (ctl.show_addresses && info.hosts[0]) {
			if (strchr(info.hosts, ' ') != NULL)
				printf("ADDRESSES=\"%s\"\n", info.hosts);
			else
				printf("ADDRESSES=%s\n", info.hosts);
		}

		if ((ctl.resolve_host) && info.hostname) {
			printf("HOSTNAME=%s\n", info.hostname);
		}

		if (ctl.revolve_ip) {
			printf("ADDRESS=%s\n", ipStr);
		}

#ifdef USE_GEOIP
		if (ctl.show_geoip) {
			if (info.geoip_ccode)
				printf("COUNTRYCODE=%s\n", info.geoip_ccode);
			if (info.geoip_country) {
				if (strchr(info.geoip_country, ' ') != NULL)
					printf("COUNTRY=\"%s\"\n", info.geoip_country);
				else
					printf("COUNTRY=%s\n", info.geoip_country);
			}
			if (info.geoip_city) {
				if (strchr(info.geoip_city, ' ') != NULL) {
					printf("CITY=\"%s\"\n", info.geoip_city);
				} else {
					printf("CITY=%s\n", info.geoip_city);
				}
			}
			if (info.geoip_coord)
				printf("COORDINATES=\"%s\"\n", info.geoip_coord);
		}
#endif
	}

	if (ctl.split) {
		if (ctl.family == AF_INET6) {
			show_split_networks_v6(&ctl, splitPrefix, &info);
		} else {
			show_split_networks_v4(&ctl, splitPrefix, &info);
		}
	}

	/* clean up */
	geo_end(&ctl);
	free(info.broadcast);
	free(info.expanded_ip);
	free(info.expanded_network);
	free(info.hostmax);
	if (info.hostmax != info.hostmin)
		free(info.hostmin);
	free(info.ip);
	free(info.netmask);
	if (info.hostmax != info.network)
		free(info.network);
	free(info.reverse_dns);
	free(ctl.splitStr);

	return 0;
}
