/* Based on MaxMind's geoiplookup.c
 *
 * Copyright (C) 2006 MaxMind LLC
 * Portions Copyright (C) 2015 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#define _GNU_SOURCE		/* asprintf */
#include <ctype.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include "ipcalc.h"

#ifdef USE_GEOIP

# include <GeoIP.h>
# include <GeoIPCity.h>

extern void _GeoIP_setup_dbfilename(void);

void geo_ipv4_lookup(struct in_addr ip, char **country, char **city, char **coord)
{
	GeoIP *gi;
	GeoIPRecord *gir;
	int country_id;

	ip.s_addr = ntohl(ip.s_addr);

	_GeoIP_setup_dbfilename();

	gi = GeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		country_id = GeoIP_id_by_ipnum(gi, ip.s_addr);
		if (country_id < 0 || country_id >= (int)GeoIP_num_countries()) {
			return;
		}
		*country = strdup(GeoIP_country_name[country_id]);

		GeoIP_delete(gi);
	}

	gi = GeoIP_open_type(GEOIP_CITY_EDITION_REV1, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		gir = GeoIP_record_by_ipnum(gi, ip.s_addr);

		if (gir && gir->city)
			*city = strdup(gir->city);

		if (gir && gir->longitude != 0 && gir->longitude != 0)
			asprintf(coord, "%f, %f", gir->latitude, gir->longitude);

		GeoIP_delete(gi);
	} else {
		gi = GeoIP_open_type(GEOIP_CITY_EDITION_REV0, GEOIP_STANDARD | GEOIP_SILENCE);
		if (gi != NULL) {
			gi->charset = GEOIP_CHARSET_UTF8;

			gir = GeoIP_record_by_ipnum(gi, ip.s_addr);

			if (gir && gir->city)
				*city = strdup(gir->city);

			if (gir && gir->longitude != 0 && gir->longitude != 0)
				asprintf(coord, "%f, %f", gir->latitude, gir->longitude);

			GeoIP_delete(gi);
		}
	}

	return;
}

void geo_ipv6_lookup(struct in6_addr *ip, char **country, char **city, char **coord)
{
	GeoIP *gi;
	GeoIPRecord *gir;
	int country_id;

	_GeoIP_setup_dbfilename();

	gi = GeoIP_open_type(GEOIP_COUNTRY_EDITION_V6, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		country_id = GeoIP_id_by_ipnum_v6(gi, (geoipv6_t)*ip);
		if (country_id < 0 || country_id >= (int)GeoIP_num_countries()) {
			return;
		}
		*country = strdup(GeoIP_country_name[country_id]);

		GeoIP_delete(gi);
	}

	gi = GeoIP_open_type(GEOIP_CITY_EDITION_REV1_V6, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		gir = GeoIP_record_by_ipnum_v6(gi, (geoipv6_t)*ip);

		if (gir && gir->city)
			*city = strdup(gir->city);

		if (gir && gir->longitude != 0 && gir->longitude != 0)
			asprintf(coord, "%f, %f", gir->latitude, gir->longitude);

		GeoIP_delete(gi);
	} else {
		gi = GeoIP_open_type(GEOIP_CITY_EDITION_REV0_V6, GEOIP_STANDARD | GEOIP_SILENCE);
		if (gi != NULL) {
			gi->charset = GEOIP_CHARSET_UTF8;

			gir = GeoIP_record_by_ipnum_v6(gi, (geoipv6_t)*ip);

			if (gir && gir->city)
				*city = strdup(gir->city);

			if (gir && gir->longitude != 0 && gir->longitude != 0)
				asprintf(coord, "%f, %f", gir->latitude, gir->longitude);

			GeoIP_delete(gi);
		}
	}

	return;
}

#endif
