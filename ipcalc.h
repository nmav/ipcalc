/*
 * Copyright (c) 2016 Red Hat, Inc. All rights reserved.
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
 */

#ifndef _IPCALC_H
#define _IPCALC_H

int __attribute__((__format__(printf, 2, 3))) safe_asprintf(char **strp, const char *fmt, ...);

#if defined(USE_GEOIP)
  void geo_ip_lookup(const char *ip, char **country, char **ccode, char **city, char  **coord);
  int geo_setup(void);
# ifndef USE_RUNTIME_LINKING
#   define geo_setup() 0
# endif
#elif defined(USE_MAXMIND)
  void geo_ip_lookup(const char *ip, char **country, char **ccode, char **city, char  **coord);
  int geo_setup(void);
# ifndef USE_RUNTIME_LINKING
#   define geo_setup() 0
# endif
#else
# define geo_ipv4_lookup(x,y,z,w,a)
# define geo_ipv6_lookup(x,y,z,w,a)
# define geo_setup() -1
#endif

char __attribute__((warn_unused_result)) *safe_strdup(const char *str);

char *calc_reverse_dns4(struct in_addr ip, unsigned prefix, struct in_addr net, struct in_addr bcast);
char *calc_reverse_dns6(struct in6_addr *ip, unsigned prefix);

uint32_t prefix2mask(int prefix);
int ipv6_prefix_to_mask(unsigned prefix, struct in6_addr *mask); 

char *ipv4_prefix_to_hosts(char *hosts, unsigned hosts_size, unsigned prefix);
char *ipv6_prefix_to_hosts(char *hosts, unsigned hosts_size, unsigned prefix);

typedef struct ip_info_st {
	char *ip;
	char *expanded_ip;
	char *expanded_network;
	char *reverse_dns;

	char *network;
	char *broadcast;	/* ipv4 only */
	char *netmask;
	char *hostname;
	char *geoip_country;
	char *geoip_ccode;
	char *geoip_city;
	char *geoip_coord;
	char hosts[64];		/* number of hosts in text */
	unsigned prefix;

	char *hostmin;
	char *hostmax;
	const char *type;
	const char *class;
} ip_info_st;

#define FLAG_RESOLVE_HOST 1
#define FLAG_RESOLVE_IP (1<<1)
#define FLAG_CHECK_ADDRESS (1<<2)
#define FLAG_SHOW_INFO (1<<3)
#define FLAG_SHOW_BROADCAST (1<<6)
#define FLAG_SHOW_NETMASK (1<<7)
#define FLAG_SHOW_NETWORK (1<<8)
#define FLAG_SHOW_PREFIX (1<<9)
#define FLAG_SHOW_MINADDR (1<<10)
#define FLAG_SHOW_MAXADDR (1<<11)
#define FLAG_SHOW_ADDRESSES (1<<12)
#define FLAG_SHOW_ADDRSPACE (1<<13)
#define FLAG_GET_GEOIP (1<<14)
#define FLAG_SHOW_GEOIP ((1<<15)|FLAG_GET_GEOIP)
#define FLAG_SHOW_ALL_INFO ((1<<16)|FLAG_SHOW_INFO)
#define FLAG_SHOW_REVERSE (1<<17)
#define FLAG_ASSUME_CLASS_PREFIX (1<<18)
#define FLAG_SPLIT (1<<19)
#define FLAG_NO_DECORATE (1<<20)

/* Flags that are not real options */
#define FLAGS_TO_IGNORE (FLAG_GET_GEOIP|FLAG_SPLIT|FLAG_NO_DECORATE|FLAG_ASSUME_CLASS_PREFIX|(1<<16))
#define FLAGS_TO_IGNORE_MASK (~FLAGS_TO_IGNORE)

void show_split_networks_v4(unsigned split_prefix, const struct ip_info_st *info, unsigned flags);
void show_split_networks_v6(unsigned split_prefix, const struct ip_info_st *info, unsigned flags);

#define KBLUE  "\x1B[34m"
#define KMAG   "\x1B[35m"
#define KRESET "\033[0m"

#define default_printf(...) color_printf(KBLUE, __VA_ARGS__)
#define dist_printf(...) color_printf(KMAG, __VA_ARGS__)

void
__attribute__ ((format(printf, 3, 4)))
color_printf(const char *color, const char *title, const char *fmt, ...);

extern int beSilent;

#endif
