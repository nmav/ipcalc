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

struct ipcalc_control {
	char *hostname;
	char *randomStr;
	char *splitStr;
	int family;
	unsigned int
		resolve_host:1,
		revolve_ip:1,
		check_address:1,
		show_info:1,
		show_broadcast:1,
		show_netmask:1,
		show_network:1,
		show_prefix:1,
		show_min_addr:1,
		show_max_addr:1,
		show_addresses:1,
		show_address_space:1,
#ifdef USE_GEOIP
		get_geoip:1,
		show_geoip:1,
#endif
		show_all:1,
		show_reverse:1,
		assume_class_prefix:1,
		split:1,
		beSilent:1,
		colors:1;
};

#ifdef USE_GEOIP
void geo_ipv4_lookup(const struct ipcalc_control *ctl, struct in_addr ip, char **country, char **ccode, char **city, char  **coord);
void geo_ipv6_lookup(const struct ipcalc_control *ctl, struct in6_addr *ip, char **country, char **ccode, char **city, char **coord);
int geo_setup(const struct ipcalc_control *ctl);
#else
# define geo_ipv4_lookup(x,y,z,w,a,b)
# define geo_ipv6_lookup(x,y,z,w,a,b)
# define geo_setup(a) -1
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

void show_split_networks_v4(const struct ipcalc_control *ctl, unsigned split_prefix, const struct ip_info_st *info);
void show_split_networks_v6(const struct ipcalc_control *ctl, unsigned split_prefix, const struct ip_info_st *info);

#define KBLUE  "\x1B[34m"
#define KMAG   "\x1B[35m"
#define KRESET "\033[0m"

void
__attribute__ ((format(printf, 4, 5)))
color_printf(const struct ipcalc_control *ctl, const char *color, const char *title, const char *fmt, ...);

extern int beSilent;
