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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * Authors:
 *   Erik Troan <ewt@redhat.com>
 *   Preston Brown <pbrown@redhat.com>
 *   David Cantrell <dcantrell@redhat.com>
 *   Nikos Mavrogiannopoulos <nmav@redhat.com>
 */

#define _GNU_SOURCE		/* asprintf */
#include <ctype.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
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

int safe_atoi(const char *s, int *ret_i)
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
  \fn struct in_addr prefix2mask(int bits)
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
struct in_addr prefix2mask(int prefix)
{
	struct in_addr mask;
	memset(&mask, 0, sizeof(mask));
	if (prefix) {
		mask.s_addr = htonl(~((1 << (32 - prefix)) - 1));
	} else {
		mask.s_addr = htonl(0);
	}
	return mask;
}

/*!
  \fn struct in_addr calc_broadcast(struct in_addr addr, int prefix)

  \brief calculate broadcast address given an IP address and a prefix length.

  \param addr an IP address in network byte order.
  \param prefix a prefix length.

  \return the calculated broadcast address for the network, in network byte
  order.
*/
struct in_addr calc_broadcast(struct in_addr addr, int prefix)
{
	struct in_addr mask = prefix2mask(prefix);
	struct in_addr broadcast;

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
struct in_addr calc_network(struct in_addr addr, int prefix)
{
	struct in_addr mask = prefix2mask(prefix);
	struct in_addr network;

	memset(&network, 0, sizeof(network));
	network.s_addr = addr.s_addr & mask.s_addr;
	return network;
}

/*!
  \fn const char *get_hostname(int family, void *addr)
  \brief returns the hostname associated with the specified IP address

  \param family the address family, either AF_INET or AF_INET6.
  \param addr an IP address to find a hostname for, in network byte order,
  should either be a pointer to a struct in_addr or a struct in6_addr.

  \return a hostname, or NULL if one cannot be determined.  Hostname is stored
  in a static buffer that may disappear at any time, the caller should copy the
  data if it needs permanent storage.
*/
char *get_hostname(int family, void *addr)
{
	struct hostent *hostinfo = NULL;
	int x;
	struct in_addr addr4;
	struct in6_addr addr6;

	if (family == AF_INET) {
		memset(&addr4, 0, sizeof(addr4));
		memcpy(&addr4, addr, sizeof(addr4));
		hostinfo = gethostbyaddr((const void *)&addr4,
					 sizeof(addr4), family);
	} else if (family == AF_INET6) {
		memset(&addr6, 0, sizeof(addr6));
		memcpy(&addr6, addr, sizeof(addr6));
		hostinfo = gethostbyaddr((const void *)&addr6,
					 sizeof(addr6), family);
	}

	if (!hostinfo)
		return NULL;

	for (x = 0; hostinfo->h_name[x]; x++) {
		hostinfo->h_name[x] = tolower(hostinfo->h_name[x]);
	}
	return hostinfo->h_name;
}

int bit_count(uint32_t i)
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

	if (c == 0)
		return -1;
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

typedef struct ip_info_st {
	char *ip;
	char *expanded_ip;
	char *expanded_network;

	char *network;
	char *broadcast;	/* ipv4 only */
	char *netmask;
	char *hostname;
	char hosts[64];		/* number of hosts in text */
	unsigned prefix;

	char *hostmin;
	char *hostmax;
	const char *type;
	const char *class;
} ip_info_st;

/* Returns powers of two in textual format */
const char *p2_table(unsigned pow)
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

const char *ipv4_net_to_type(struct in_addr net)
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

	return "Internet or Reserved for Future use";
}

static
const char *ipv4_net_to_class(struct in_addr net)
{
	unsigned byte1 = (ntohl(net.s_addr) >> 24) & 0xff;

	if (byte1 >= 0 && byte1 < 128) {
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

	if (byte1 >= 0 && byte1 < 128) {
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

int get_ipv4_info(const char *ipStr, int prefix, ip_info_st * info,
		  int beSilent, int showHostname)
{
	struct in_addr ip, netmask, network, broadcast, minhost, maxhost;
	char namebuf[INET6_ADDRSTRLEN + 1];
	char errBuf[250];
	unsigned hosts;

	memset(info, 0, sizeof(*info));

	if (inet_pton(AF_INET, ipStr, &ip) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv4 address: %s\n",
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
			if (asprintf(&tmp, "%s.0", ipStr) == -1) {
				fprintf(stderr,
					"Memory allocation failure line %d\n",
					__LINE__);
				abort();
			}
			ipStr = tmp;
		}
	} else {		/* assume good old days classful Internet */
		prefix = default_ipv4_prefix(ip);
	}

	if (prefix > 32) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv4 prefix %d\n", prefix);
		return -1;
	}

	if (inet_ntop(AF_INET, &ip, namebuf, sizeof(namebuf)) == 0) {
		if (!beSilent)
			fprintf(stderr,
				"ipcalc: error calculating the IPv6 network\n");
		return -1;
	}
	info->ip = strdup(namebuf);

	netmask = prefix2mask(prefix);
	memset(&namebuf, '\0', sizeof(namebuf));

	if (inet_ntop(AF_INET, &netmask, namebuf, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr, "Memory allocation failure line %d\n",
			__LINE__);
		abort();
	}
	info->netmask = strdup(namebuf);
	info->prefix = prefix;

	broadcast = calc_broadcast(ip, prefix);

	memset(&namebuf, '\0', sizeof(namebuf));
	if (inet_ntop(AF_INET, &broadcast, namebuf, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr, "Memory allocation failure line %d\n",
			__LINE__);
		abort();
	}
	info->broadcast = strdup(namebuf);

	network = calc_network(ip, prefix);

	memset(&namebuf, '\0', sizeof(namebuf));
	if (inet_ntop(AF_INET, &network, namebuf, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr, "Memory allocation failure line %d\n",
			__LINE__);
		abort();
	}

	info->network = strdup(namebuf);

	info->type = ipv4_net_to_type(network);
	info->class = ipv4_net_to_class(network);

	if (prefix < 32) {
		memcpy(&minhost, &network, sizeof(minhost));

		if (prefix <= 30)
			minhost.s_addr = htonl(ntohl(minhost.s_addr) | 1);
		if (inet_ntop(AF_INET, &minhost, namebuf, INET_ADDRSTRLEN) ==
		    NULL) {
			fprintf(stderr, "Memory allocation failure line %d\n",
				__LINE__);
			abort();
		}
		info->hostmin = strdup(namebuf);

		memcpy(&maxhost, &network, sizeof(minhost));
		maxhost.s_addr |= ~netmask.s_addr;
		if (prefix <= 30) {
			maxhost.s_addr = htonl(ntohl(maxhost.s_addr) - 1);
		}
		if (inet_ntop(AF_INET, &maxhost, namebuf, sizeof(namebuf)) == 0) {
			if (!beSilent)
				fprintf(stderr,
					"ipcalc: error calculating the IPv6 network\n");
			return -1;
		}

		info->hostmax = strdup(namebuf);
	} else {
		info->hostmin = info->network;
		info->hostmax = info->network;
	}

	if (prefix >= 31) {
		snprintf(info->hosts, sizeof(info->hosts), "%s", p2_table(32 - prefix));
	} else {
		hosts = (1 << (32 - prefix)) - 2;
		snprintf(info->hosts, sizeof(info->hosts), "%u", hosts);
	}

	if (showHostname) {
		info->hostname = get_hostname(AF_INET, &ip);

		if (info->hostname == NULL) {
			if (!beSilent) {
				sprintf(errBuf,
					"ipcalc: cannot find hostname for %s",
					ipStr);
				herror(errBuf);
			}
			return -1;
		}
	}

	return 0;
}

char *ipv6_prefix_to_mask(unsigned prefix, struct in6_addr *mask)
{
	struct in6_addr in6;
	int i, j;
	char buf[128];

	if (prefix == 0 || prefix > 128)
		return NULL;

	memset(&in6, 0x0, sizeof(in6));
	for (i = prefix, j = 0; i > 0; i -= 8, j++) {
		if (i >= 8) {
			in6.s6_addr[j] = 0xff;
		} else {
			in6.s6_addr[j] = (unsigned long)(0xffU << (8 - i));
		}
	}

	if (inet_ntop(AF_INET6, &in6, buf, sizeof(buf)) == NULL)
		return NULL;

	memcpy(mask, &in6, sizeof(*mask));
	return strdup(buf);
}

char *ipv6_net_to_type(struct in6_addr *net, int prefix)
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

	return strdup(buf);
}

int get_ipv6_info(const char *ipStr, int prefix, ip_info_st * info,
		  int beSilent, int showHostname)
{
	struct in6_addr ip6, mask, network;
	char errBuf[250];
	unsigned i;

	memset(info, 0, sizeof(*info));

	if (inet_pton(AF_INET6, ipStr, &ip6) <= 0) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv6 address: %s\n",
				ipStr);
		return -1;
	}

	/* expand  */
	info->expanded_ip = expand_ipv6(&ip6);

	if (inet_ntop(AF_INET6, &ip6, errBuf, sizeof(errBuf)) == 0) {
		if (!beSilent)
			fprintf(stderr,
				"ipcalc: error calculating the IPv6 network\n");
		return -1;
	}

	info->ip = strdup(errBuf);

	if (prefix == 0 || prefix > 128) {
		if (!beSilent)
			fprintf(stderr, "ipcalc: bad IPv6 prefix: %d\n",
				prefix);
		return -1;
	} else if (prefix < 0) {
		prefix = 128;
	}

	info->prefix = prefix;

	info->netmask = ipv6_prefix_to_mask(prefix, &mask);
	if (!info->netmask) {
		if (!beSilent)
			fprintf(stderr,
				"ipcalc: error converting IPv6 prefix: %d\n",
				prefix);
		return -1;
	}

	for (i = 0; i < sizeof(struct in6_addr); i++)
		network.s6_addr[i] = ip6.s6_addr[i] & mask.s6_addr[i];

	if (inet_ntop(AF_INET6, &network, errBuf, sizeof(errBuf)) == 0) {
		if (!beSilent)
			fprintf(stderr,
				"ipcalc: error calculating the IPv6 network\n");
		return -1;
	}

	info->network = strdup(errBuf);

	info->expanded_network = expand_ipv6(&network);
	info->type = ipv6_net_to_type(&network, prefix);

	if (prefix < 128) {
		info->hostmin = strdup(errBuf);

		for (i = 0; i < sizeof(struct in6_addr); i++)
			network.s6_addr[i] |= ~mask.s6_addr[i];
		if (inet_ntop(AF_INET6, &network, errBuf, sizeof(errBuf)) == 0) {
			if (!beSilent)
				fprintf(stderr,
					"ipcalc: error calculating the IPv6 network\n");
			return -1;
		}

		info->hostmax = strdup(errBuf);
	} else {
		info->hostmin = info->network;
		info->hostmax = info->network;
	}

	snprintf(info->hosts, sizeof(info->hosts), "%s", p2_table(128 - prefix));

	if (showHostname) {
		info->hostname = get_hostname(AF_INET6, &ip6);
		if (info->hostname == NULL) {
			if (!beSilent) {
				sprintf(errBuf,
					"ipcalc: cannot find hostname for %s",
					ipStr);
				herror(errBuf);
			}
			return -1;
		}
	}
	return 0;
}

static int randomize(void *ptr, unsigned size)
{
	int fd, ret;

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

static char *generate_ip_network(int ipv6, unsigned prefix)
{
	struct timespec ts;
	char ipbuf[64];
	char *p = NULL;

	if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) < 0)
		return NULL;

	if (ipv6) {
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
		uint8_t byte1, byte2, byte3, byte4;

		if (prefix >= 16 && c < 2) {
			if (c == 1) {
				byte1 = 192;
				byte2 = 168;
				byte3 = (ts.tv_nsec >> 16) & 0xff;
				byte4 = (ts.tv_nsec >> 8) & 0xff;
			} else {
				byte1 = 172;
				byte2 = 16 | ((ts.tv_nsec >> 4) & 0x0f);
				byte4 = (ts.tv_nsec >> 16) & 0xff;
				byte3 = (ts.tv_nsec >> 8) & 0xff;
			}
		} else {
			byte1 = 10;
			byte2 = (ts.tv_nsec >> 16) & 0xff;
			byte3 = (ts.tv_nsec >> 8) & 0xff;
			byte4 = (ts.tv_nsec) & 0xff;
		}

		net.s_addr =
		    (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4;
		net.s_addr = htonl(net.s_addr);

		if (inet_ntop(AF_INET, &net, ipbuf, sizeof(ipbuf)) == NULL)
			return NULL;
	}

	if (asprintf(&p, "%s/%u", ipbuf, prefix) == -1)
		return NULL;

	return p;
}

static
int str_to_prefix(int ipv6, const char *prefixStr)
{
	int prefix, r;
	if (!ipv6 && strchr(prefixStr, '.')) {	/* prefix is 255.x.x.x */
		prefix = ipv4_mask_to_int(prefixStr);
	} else {
		r = safe_atoi(prefixStr, &prefix);
		if (r != 0) {
			return -1;
		}
	}

	if (prefix <= 0 || ((ipv6 && prefix > 128) || (!ipv6 && prefix > 32))) {
		return -1;
	}
	return prefix;
}

/*!
  \fn main(int argc, const char **argv)
  \brief wrapper program for ipcalc functions.

  This is a wrapper program for the functions that the ipcalc library provides.
  It can be used from shell scripts or directly from the command line.

  For more information, please see the ipcalc(1) man page.
*/
int main(int argc, const char **argv)
{
	int showBroadcast = 0, showPrefix = 0, showNetwork = 0;
	int showHostname = 0, showNetmask = 0, showAddrSpace = 0;
	int showHostMax = 0, showHostMin = 0, showHosts = 0;
	int beSilent = 0;
	int doCheck = 0, familyIPv6 = 0, doInfo = 0;
	int rc, familyIPv4 = 0, doRandom = 0;
	poptContext optCon;
	char *ipStr, *prefixStr, *netmaskStr = NULL, *chptr;
	int prefix = -1;
	ip_info_st info;
	int r = 0;

	struct poptOption optionsTable[] = {
		{"check", 'c', 0, &doCheck, 0,
		 "Validate IP address",},
		{"random-private", 'r', 0, &doRandom, 0,
		 "Generate a random private IP network",},
		{"info", 'i', 0, &doInfo, 0,
		 "Print information on the provided IP address",},
		{"ipv4", '4', 0, &familyIPv4, 0,
		 "Explicitly specify the IPv4 address family",},
		{"ipv6", '6', 0, &familyIPv6, 0,
		 "Explicitly specify the IPv6 address family",},
		{"broadcast", 'b', 0, &showBroadcast, 0,
		 "Display calculated broadcast address",},
		{"hostname", 'h', 0, &showHostname, 0,
		 "Show hostname determined via DNS"},
		{"netmask", 'm', 0, &showNetmask, 0,
		 "Display netmask for IP"},
		{"network", 'n', 0, &showNetwork, 0,
		 "Display network address",},
		{"prefix", 'p', 0, &showPrefix, 0,
		 "Display network prefix",},
		{"minaddr", '\0', 0, &showHostMin, 0,
		 "Display the minimum address in the network",},
		{"maxaddr", '\0', 0, &showHostMax, 0,
		 "Display the maximum address in the network",},
		{"addresses", '\0', 0, &showHosts, 0,
		 "Display the maximum number of addresses in the network",},
		{"addrspace", '\0', 0, &showAddrSpace, 0,
		 "Display the address space the network resides on",},
		{"silent", 's', 0, &beSilent, 0,
		 "Don't ever display error messages"},
		POPT_AUTOHELP {NULL, '\0', 0, 0, 0, NULL, NULL}
	};

	optCon = poptGetContext("ipcalc", argc, argv, optionsTable, 0);
	poptReadDefaultConfig(optCon, 1);

	if ((rc = poptGetNextOpt(optCon)) < -1) {
		if (!beSilent) {
			fprintf(stderr, "ipcalc: bad argument %s: %s\n",
				poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
				poptStrerror(rc));
			poptPrintHelp(optCon, stderr, 0);
		}
		return 1;
	}

	if (!(ipStr = (char *)poptGetArg(optCon))) {
		if (!beSilent) {
			if (doRandom)
				fprintf(stderr,
					"ipcalc: network prefix expected\n");
			else
				fprintf(stderr,
					"ipcalc: ip address expected\n");
			poptPrintHelp(optCon, stderr, 0);
		}
		return 1;
	}

	if (doRandom) {
		prefix = str_to_prefix(familyIPv6, ipStr);
		if (prefix <= 0) {
			if (!beSilent)
				fprintf(stderr,
					"ipcalc: bad prefix: %s\n", ipStr);
			return 1;
		}

		ipStr = generate_ip_network(familyIPv6, prefix);
		if (ipStr == NULL) {
			if (!beSilent)
				fprintf(stderr,
					"ipcalc: cannot generate network with prefix: %u\n",
					prefix);
			return 1;
		}
	}

	/* if there is a : in the address, it is an IPv6 address.
	 * Note that we allow -4, and -6 to be given explicitly, so
	 * that the tool can be used to check for a valid IPv4 or IPv6
	 * address.
	 */
	if (familyIPv4 == 0 && strchr(ipStr, ':') != NULL) {
		familyIPv6 = 1;
	}

	if (strchr(ipStr, '/') != NULL) {
		prefixStr = strchr(ipStr, '/') + 1;
		prefixStr--;
		*prefixStr = '\0';	/* fix up ipStr */
		prefixStr++;
	} else {
		prefixStr = NULL;
	}

	if (prefixStr != NULL) {
		prefix = str_to_prefix(familyIPv6, prefixStr);
		if (prefix <= 0) {
			if (!beSilent)
				fprintf(stderr,
					"ipcalc: bad prefix: %s\n", prefixStr);
			return 1;
		}
	}

	if (familyIPv6) {
		r = get_ipv6_info(ipStr, prefix, &info, beSilent, showHostname);
	} else {
		if (showBroadcast || showNetwork || showPrefix) {
			if (netmaskStr && prefix >= 0) {
				if (!beSilent) {
					fprintf(stderr,
						"ipcalc: both netmask and prefix specified\n");
					poptPrintHelp(optCon, stderr, 0);
				}
				return 1;
			}
		}

		if (prefix == -1 && netmaskStr) {
			prefix = ipv4_mask_to_int(netmaskStr);
			if (prefix < 0) {
				if (!beSilent)
					fprintf(stderr,
						"ipcalc: bad prefix: %s\n",
						prefixStr);
				return 1;
			}
		}
		r = get_ipv4_info(ipStr, prefix, &info, beSilent, showHostname);
	}

	if (r < 0) {
		return 1;
	}

	if ((chptr = (char *)poptGetArg(optCon))) {
		if (!beSilent) {
			fprintf(stderr, "ipcalc: unexpected argument: %s\n",
				chptr);
			poptPrintHelp(optCon, stderr, 0);
		}
		return 1;
	}

	if (doCheck)
		return 0;

	/* if no option is given, print information on IP */
	if (!(showNetmask | showPrefix | showBroadcast | showNetwork |
	      showHostMin | showHostMax | showHostname | doInfo |
	      showHosts | showAddrSpace)) {
		doInfo = 1;
	}

	poptFreeContext(optCon);

	/* we know what we want to display now, so display it. */
	if (doInfo) {
		unsigned single_host = 0;

		if ((familyIPv6 && info.prefix == 128) ||
		    (!familyIPv6 && info.prefix == 32)) {
			single_host = 1;
		}

		if ((!doRandom || single_host) &&
		    (single_host || strcmp(info.network, info.ip) != 0)) {
			if (info.expanded_ip)
				printf("Full Address:\t%s\n", info.expanded_ip);
			printf("Address:\t%s\n", info.ip);
		}

		if (!single_host) {
			if (info.expanded_network)
				printf("Full Network:\t%s\n",
				       info.expanded_network);
			printf("Network:\t%s/%u\n", info.network, info.prefix);
			if (info.type)
				printf("Address space:\t%s\n", info.type);
			if (info.class)
				printf("Address class:\t%s\n", info.class);
			printf("Netmask:\t%s = %u\n", info.netmask,
			       info.prefix);

			if (info.broadcast)
				printf("Broadcast:\t%s\n", info.broadcast);
			printf("\n");

			if (info.hostmin)
				printf("HostMin:\t%s\n", info.hostmin);
			if (info.hostmax)
				printf("HostMax:\t%s\n", info.hostmax);

			if (familyIPv6 && info.prefix < 112)
				printf("Hosts/Net:\t2^(%u) = %s\n", 128-info.prefix, info.hosts);
			else
				printf("Hosts/Net:\t%s\n", info.hosts);
		} else {
			if (info.type)
				printf("Address space:\t%s\n", info.type);
			if (info.class)
				printf("Address class:\t%s\n", info.class);

		}
	} else {

		if (showNetmask) {
			printf("NETMASK=%s\n", info.netmask);
		}

		if (showPrefix) {
			printf("PREFIX=%u\n", info.prefix);
		}

		if (showBroadcast && !familyIPv6) {
			printf("BROADCAST=%s\n", info.broadcast);
		}

		if (showNetwork) {
			printf("NETWORK=%s\n", info.network);
		}

		if (showHostMin && info.hostmin) {
			printf("MINADDR=%s\n", info.hostmin);
		}

		if (showHostMax && info.hostmax) {
			printf("MAXADDR=%s\n", info.hostmax);
		}

		if (showAddrSpace && info.type) {
			printf("ADDRSPACE=\"%s\"\n", info.type);
		}

		if (showHosts) {
			printf("ADDRESSES=\"%s\"\n", info.hosts);
		}

		if (showHostname) {
			printf("HOSTNAME=%s\n", info.hostname);
		}
	}

	return 0;
}
