/*
 * Copyright (c) 1997-2009 Red Hat, Inc. All rights reserved.
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
 */

#include <ctype.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

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

int safe_atoi(const char *s, int *ret_i) {
        char *x = NULL;
        long l;

        errno = 0;
        l = strtol(s, &x, 0);

        if (!x || x == s || *x || errno)
                return errno > 0 ? -errno : -EINVAL;

        if ((long) (int) l != l)
                return -ERANGE;

        *ret_i = (int) l;
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
struct in_addr prefix2mask(int prefix) {
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
  \fn int mask2prefix(struct in_addr mask)
  \brief calculates the number of bits masked off by a netmask.

  This function calculates the significant bits in an IP address as specified by
  a netmask.  See also \ref prefix2mask.

  \param mask is the netmask, specified as an struct in_addr in network byte order.
  \return the number of significant bits.  */
int mask2prefix(struct in_addr mask)
{
    int count;
    uint32_t saddr = ntohl(mask.s_addr);

    for (count=0; saddr > 0; count++) {
        saddr=saddr << 1;
    }

    return count;
}

/*!
  \fn struct in_addr default_netmask(struct in_addr addr)

  \brief returns the default (canonical) netmask associated with specified IP
  address.

  When the Internet was originally set up, various ranges of IP addresses were
  segmented into three network classes: A, B, and C.  This function will return
  a netmask that is associated with the IP address specified defining where it
  falls in the predefined classes.

  \param addr an IP address in network byte order.
  \return a netmask in network byte order.  */
struct in_addr default_netmask(struct in_addr addr)
{
    uint32_t saddr = addr.s_addr;
    struct in_addr mask;

    memset(&mask, 0, sizeof(mask));

    if (((ntohl(saddr) & 0xFF000000) >> 24) <= 127)
        mask.s_addr = htonl(0xFF000000);
    else if (((ntohl(saddr) & 0xFF000000) >> 24) <= 191)
        mask.s_addr = htonl(0xFFFF0000);
    else
        mask.s_addr = htonl(0xFFFFFF00);

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
    struct hostent * hostinfo = NULL;
    int x;
    struct in_addr addr4;
    struct in6_addr addr6;

    if (family == AF_INET) {
        memset(&addr4, 0, sizeof(addr4));
        memcpy(&addr4, addr, sizeof(addr4));
        hostinfo = gethostbyaddr((const void *) &addr4,
                                 sizeof(addr4), family);
    } else if (family == AF_INET6) {
        memset(&addr6, 0, sizeof(addr6));
        memcpy(&addr6, addr, sizeof(addr6));
        hostinfo = gethostbyaddr((const void *) &addr6,
                                 sizeof(addr6), family);
    }

    if (!hostinfo)
        return NULL;

    for (x=0; hostinfo->h_name[x]; x++) {
        hostinfo->h_name[x] = tolower(hostinfo->h_name[x]);
    }
    return hostinfo->h_name;
}

/*!
  \fn main(int argc, const char **argv)
  \brief wrapper program for ipcalc functions.

  This is a wrapper program for the functions that the ipcalc library provides.
  It can be used from shell scripts or directly from the command line.

  For more information, please see the ipcalc(1) man page.
*/
int main(int argc, const char **argv) {
    int showBroadcast = 0, showPrefix = 0, showNetwork = 0;
    int showHostname = 0, showNetmask = 0;
    int beSilent = 0;
    int doCheck = 0, familyIPv6 = 0;
    int rc;
    poptContext optCon;
    char *ipStr, *prefixStr, *netmaskStr, *chptr;
    char *hostName = NULL;
    char namebuf[INET6_ADDRSTRLEN+1];
    struct in_addr ip, netmask, network, broadcast;
    struct in6_addr ip6;
    int prefix = -1;
    char errBuf[250];
    struct poptOption optionsTable[] = {
        { "check", 'c', 0, &doCheck, 0,
          "Validate IP address for specified address family", },
        { "ipv4", '4', 0, NULL, 0,
          "IPv4 address family (deprecated)", },
        { "ipv6", '6', 0, NULL, 0,
          "IPv6 address family (deprecated)", },
        { "broadcast", 'b', 0, &showBroadcast, 0,
          "Display calculated broadcast address", },
        { "hostname", 'h', 0, &showHostname, 0,
          "Show hostname determined via DNS" },
        { "netmask", 'm', 0, &showNetmask, 0,
          "Display default netmask for IP (class A, B, or C)" },
        { "network", 'n', 0, &showNetwork, 0,
          "Display network address", },
        { "prefix", 'p', 0, &showPrefix, 0,
          "Display network prefix", },
        { "silent", 's', 0, &beSilent, 0,
          "Don't ever display error messages" },
        POPT_AUTOHELP
        { NULL, '\0', 0, 0, 0, NULL, NULL }
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

    if (!(ipStr = (char *) poptGetArg(optCon))) {
        if (!beSilent) {
            fprintf(stderr, "ipcalc: ip address expected\n");
            poptPrintHelp(optCon, stderr, 0);
        }
        return 1;
    }

    /* if there is a : in the address, it is an IPv6 address */
    if (strchr(ipStr,':') != NULL) {
        familyIPv6=1;
    }

    if (strchr(ipStr,'/') != NULL) {
        prefixStr = strchr(ipStr, '/') + 1;
        prefixStr--;
        *prefixStr = '\0';  /* fix up ipStr */
        prefixStr++;
    } else {
        prefixStr = NULL;
    }

    if (prefixStr != NULL) {
    	int r = 0;
        r = safe_atoi(prefixStr, &prefix);
        if (r != 0 || prefix < 0 || ((familyIPv6 && prefix > 128) || (!familyIPv6 && prefix > 32))) {
            if (!beSilent)
                fprintf(stderr, "ipcalc: bad prefix: %s\n", prefixStr);
            return 1;
        }
    }

    if (showBroadcast || showNetwork || showPrefix) {
        if (!(netmaskStr = (char *) poptGetArg(optCon)) && (prefix < 0)) {
            if (!beSilent) {
                fprintf(stderr, "ipcalc: netmask or prefix expected\n");
                poptPrintHelp(optCon, stderr, 0);
            }
            return 1;
        } else if (netmaskStr && prefix >= 0) {
            if (!beSilent) {
                fprintf(stderr, "ipcalc: both netmask and prefix specified\n");
                poptPrintHelp(optCon, stderr, 0);
            }
            return 1;
        } else if (netmaskStr) {
            if (inet_pton(AF_INET, netmaskStr, &netmask) <= 0) {
                if (!beSilent)
                    fprintf(stderr, "ipcalc: bad netmask: %s\n", netmaskStr);
                return 1;
            }
            prefix = mask2prefix(netmask);
        }
    }

    if ((chptr = (char *) poptGetArg(optCon))) {
        if (!beSilent) {
            fprintf(stderr, "ipcalc: unexpected argument: %s\n", chptr);
            poptPrintHelp(optCon, stderr, 0);
        }
        return 1;
    }

    /* Handle CIDR entries such as 172/8 */
    if (prefix >= 0 && !familyIPv6) {
        char *tmp = ipStr;
        int i;

        for (i=3; i> 0; i--) {
            tmp = strchr(tmp,'.');
            if (!tmp)
                break;
            else
                tmp++;
        }

        tmp = NULL;
        for (; i>0; i--) {
            if (asprintf(&tmp, "%s.0", ipStr) == -1) {
                fprintf(stderr, "Memory allocation failure line %d\n", __LINE__);
                abort();
            }
            ipStr = tmp;
        }
    }

    if (!familyIPv6) {
        if (inet_pton(AF_INET, ipStr, &ip) <= 0) {
            if (!beSilent)
                fprintf(stderr, "ipcalc: bad IPv4 address: %s\n", ipStr);
            return 1;
        } else if (prefix > 32) {
            if (!beSilent)
                fprintf(stderr, "ipcalc: bad IPv4 prefix %d\n", prefix);
            return 1;
        } else {
            if (doCheck)
                return 0;
        }
    }

    if (familyIPv6) {
        if (inet_pton(AF_INET6, ipStr, &ip6) <= 0) {
            if (!beSilent)
                fprintf(stderr, "ipcalc: bad IPv6 address: %s\n", ipStr);
            return 1;
        } else if (prefix > 128) {
            if (!beSilent)
                fprintf(stderr, "ipcalc: bad IPv6 prefix %d\n", prefix);
            return 1;
        } else {
            if (doCheck)
                return 0;
        }
    }

    if (familyIPv6 &&
        (showBroadcast || showNetmask || showNetwork || showPrefix)) {
        if (!beSilent) {
            fprintf(stderr, "ipcalc: unable to show setting for IPv6\n");
        }
        return 1;
    }

    if (!familyIPv6 &&
        !(showNetmask|showPrefix|showBroadcast|showNetwork|showHostname)) {
        poptPrintHelp(optCon, stderr, 0);
        return 1;
    }

    poptFreeContext(optCon);

    /* we know what we want to display now, so display it. */

    if (showNetmask) {
        if (prefix >= 0) {
            netmask = prefix2mask(prefix);
        } else {
            netmask = default_netmask(ip);
            prefix = mask2prefix(netmask);
        }

        memset(&namebuf, '\0', sizeof(namebuf));

        if (inet_ntop(AF_INET, &netmask, namebuf, INET_ADDRSTRLEN) == NULL) {
            fprintf(stderr, "Memory allocation failure line %d\n", __LINE__);
            abort();
        }

        printf("NETMASK=%s\n", namebuf);
    }

    if (showPrefix) {
        if (prefix == -1)
            prefix = mask2prefix(ip);
        printf("PREFIX=%d\n", prefix);
    }

    if (showBroadcast) {
        broadcast = calc_broadcast(ip, prefix);
        memset(&namebuf, '\0', sizeof(namebuf));

        if (inet_ntop(AF_INET, &broadcast, namebuf, INET_ADDRSTRLEN) == NULL) {
            fprintf(stderr, "Memory allocation failure line %d\n", __LINE__);
            abort();
        }

        printf("BROADCAST=%s\n", namebuf);
    }

    if (showNetwork) {
        network = calc_network(ip, prefix);
        memset(&namebuf, '\0', sizeof(namebuf));

        if (inet_ntop(AF_INET, &network, namebuf, INET_ADDRSTRLEN) == NULL) {
            fprintf(stderr, "Memory allocation failure line %d\n", __LINE__);
            abort();
        }

        printf("NETWORK=%s\n", namebuf);
    }

    if (showHostname) {
        if (!familyIPv6) {
            hostName = get_hostname(AF_INET, &ip);
        } else {
            hostName = get_hostname(AF_INET6, &ip6);
        }

        if (hostName == NULL) {
            if (!beSilent) {
                sprintf(errBuf, "ipcalc: cannot find hostname for %s", ipStr);
                herror(errBuf);
            }
            return 1;
        }

        printf("HOSTNAME=%s\n", hostName);
    }

    return 0;
}
