/*
 * Copyright (c) 2003-2016  Simon Ekstrand
 * Copyright (c) 2010-2016  Joachim Nilsson
 * Copyright (c) 2016 Nikos Mavrogiannopoulos
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *  
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <error.h>

#include "ipcalc.h"

static const char *numtoquad(uint32_t num)
{
	static char quad[64];

	num = htonl(num);
	return inet_ntop(AF_INET, &num, quad, sizeof(quad));
}

void show_split_networks_v4(const struct ipcalc_control *ctl, unsigned split_prefix, const struct ip_info_st *info)
{
	char buf[64];
	uint32_t diff, start, end;
	size_t maxlen = 0;
	unsigned count;
	uint32_t splitmask = ntohl(prefix2mask(split_prefix));
	uint32_t nmask = ntohl(prefix2mask(info->prefix));
	struct in_addr net, broadcast;

	if (splitmask < nmask) {
		if (!ctl->beSilent)
			error(EXIT_FAILURE, 0,
				"cannot subnet to /%d with this base network, use a prefix > /%d",
				split_prefix, info->prefix);
		exit(EXIT_FAILURE);
	}

	printf("[Split networks]\n");

	if (inet_pton(AF_INET, info->network, &net) <= 0) {
		if (!ctl->beSilent)
			error(EXIT_FAILURE, 0,
				"bad IPv4 address: %s", info->network);
		exit(EXIT_FAILURE);
	}
	net.s_addr = ntohl(net.s_addr);

	if (inet_pton(AF_INET, info->broadcast, &broadcast) <= 0) {
		if (!ctl->beSilent)
			error(EXIT_FAILURE, 0,
				"bad broadcast address: %s", info->broadcast);
		exit(EXIT_FAILURE);
	}
	broadcast.s_addr = ntohl(broadcast.s_addr);

	diff  = 0xffffffff - splitmask + 1;
	start = net.s_addr;
	end   = net.s_addr + diff - 1;

	/* Figure out max width of a network string. */
	while (1) {
		size_t len;

		len = snprintf(buf, sizeof(buf), "%s", numtoquad(start));
		if (len > maxlen)
			maxlen = len;

		start += diff;
		if (end == 0xffffffff || end >= broadcast.s_addr)
			break;
		end += diff;
	}

	start = net.s_addr;
	end = net.s_addr + diff - 1;
	count = 0;
	while (1) {
		color_printf(ctl, KBLUE, "Network:\t", "%s/%u\n", numtoquad(start), split_prefix);

		start += diff;
		if (end == 0xffffffff || end >= broadcast.s_addr)
			break;
		end += diff;
		count++;
	}

	color_printf(ctl, KMAG, "\nTotal:  \t", "%u\n", count);
	color_printf(ctl, KMAG, "Hosts/Net:\t", "%s\n", ipv4_prefix_to_hosts(buf, sizeof(buf), split_prefix));
}

static const char *ipv6tostr(struct in6_addr *ip)
{
	static char str[64];

	return inet_ntop(AF_INET6, ip, str, sizeof(str));
}

static void v6add(struct in6_addr *a, const struct in6_addr *b)
{
	int i, j;
	uint32_t tmp;

	for (i = 15; i >= 0; i--) {
		tmp = (uint32_t)a->s6_addr[i] + (uint32_t)b->s6_addr[i];
		if (tmp > 0xff && i > 0) {
			j = i - 1;
			for (j = i - 1; j >= 0; j--) {
				a->s6_addr[j]++;
				if (a->s6_addr[j] != 0)
					break;
			}
		}

		a->s6_addr[i] = tmp & 0xff;
	}
}

void show_split_networks_v6(const struct ipcalc_control *ctl, unsigned split_prefix, const struct ip_info_st *info)
{
	int i, j, k;
	unsigned count;
	struct in6_addr splitmask, net, netmask, sdiff, ediff, start, end, tmpaddr, netlast;
	char buf[32];

	if (inet_pton(AF_INET6, info->network, &net) <= 0) {
		if (!ctl->beSilent)
			error(EXIT_FAILURE, 0, "bad IPv6 network: %s", info->network);
		exit(EXIT_FAILURE);
	}

	if (inet_pton(AF_INET6, info->hostmax, &netlast) <= 0) {
		if (!ctl->beSilent)
			error(EXIT_FAILURE, 0, "bad IPv6 address: %s", info->hostmax);
		exit(EXIT_FAILURE);
	}

	if (inet_pton(AF_INET6, info->netmask, &netmask) <= 0) {
		if (!ctl->beSilent)
			error(EXIT_FAILURE, 0, "bad IPv6 mask: %s", info->netmask);
		exit(EXIT_FAILURE);
	}

	if (ipv6_prefix_to_mask(split_prefix, &splitmask) < 0) {
		if (!ctl->beSilent)
			error(EXIT_FAILURE, 0, "bad IPv6 prefix: %d", split_prefix);
		exit(EXIT_FAILURE);
	}

	i = 0;
	j = 0;
	do {
		if (splitmask.s6_addr[i] > netmask.s6_addr[i])
			j = 1;
		if (netmask.s6_addr[i] > splitmask.s6_addr[i])
			j = 2;
		i++;
	} while (i < 16 && !j);

	if (j == 2) {
		if (!ctl->beSilent)
			error(EXIT_FAILURE, 0,
				"cannot subnet to /%d with this base network, use a prefix > /%d",
				split_prefix, info->prefix);
		exit(EXIT_FAILURE);
	}

	memset(&sdiff, 0, sizeof(sdiff));
	memset(&ediff, 0, sizeof(ediff));

	for (i = 0; i < 16; i++) {
		if (splitmask.s6_addr)
			sdiff.s6_addr[i] = 0xff - splitmask.s6_addr[i];
		end.s6_addr[i] = net.s6_addr[i] + sdiff.s6_addr[i];
	}

	memcpy(&start, &net, sizeof(net));
	memcpy(&ediff, &sdiff, sizeof(sdiff));

	memset(&tmpaddr, 0, sizeof(tmpaddr));
	tmpaddr.s6_addr[15] = 1;
	v6add(&sdiff, &tmpaddr);

	printf("[Split networks]\n");

	i = count = 0;
	while (!i) {
		color_printf(ctl, KBLUE, "Network:\t", "%s/%u\n", ipv6tostr(&start), split_prefix);

		v6add(&start, &sdiff);

		j = 0;
		for (k = 0; k < 16; k += 2)
			if (end.s6_addr[k] != 0xff && end.s6_addr[k + 1] != 0xff)
				j = 1;
		if (!j)
			i = 1;

		j = 0;
		k = 0;
		do {
			if (end.s6_addr[k] > netlast.s6_addr[k])
				j = 1;
			if (netlast.s6_addr[k] > end.s6_addr[k])
				j = 2;
			k++;
		} while (k < 16 && !j);

		if (!j || j == 1)
			i = 1;

		memset(&end, 0, sizeof(end));

		v6add(&end, &start);
		v6add(&end, &ediff);
		count++;
	}

	color_printf(ctl, KMAG, "\nTotal:  \t", "%u\n", count);
	color_printf(ctl, KMAG, "Hosts/Net:\t", "%s\n", ipv6_prefix_to_hosts(buf, sizeof(buf), split_prefix));
}

