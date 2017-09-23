/*
 * Copyright (c) 2015 Red Hat, Inc. All rights reserved.
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

#define _GNU_SOURCE		/* asprintf */
#include <ctype.h>
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

# ifdef USE_DYN_GEOIP
#  include <dlfcn.h>

typedef void (*_GeoIP_setup_dbfilename_func)(void);
typedef GeoIP * (*GeoIP_open_type_func)(int type, int flags);
typedef const char * (*GeoIP_country_name_by_id_func)(GeoIP * gi, int id);
typedef void (*GeoIP_delete_func)(GeoIP * gi);
typedef GeoIPRecord * (*GeoIP_record_by_ipnum_func)(GeoIP * gi, unsigned long ipnum);
typedef int (*GeoIP_id_by_ipnum_func)(GeoIP * gi, unsigned long ipnum);
typedef int (*GeoIP_id_by_ipnum_v6_func)(GeoIP * gi, geoipv6_t ipnum);
typedef GeoIPRecord *(*GeoIP_record_by_ipnum_v6_func)(GeoIP * gi, geoipv6_t ipnum);
typedef const char *(*GeoIP_code_by_id_func)(int id);

static _GeoIP_setup_dbfilename_func p_GeoIP_setup_dbfilename;
static GeoIP_open_type_func pGeoIP_open_type;
static GeoIP_country_name_by_id_func pGeoIP_country_name_by_id;
static GeoIP_code_by_id_func pGeoIP_code_by_id;
static GeoIP_delete_func pGeoIP_delete;
static GeoIP_record_by_ipnum_func pGeoIP_record_by_ipnum;
static GeoIP_id_by_ipnum_func pGeoIP_id_by_ipnum;
static GeoIP_id_by_ipnum_v6_func pGeoIP_id_by_ipnum_v6;
static GeoIP_record_by_ipnum_v6_func pGeoIP_record_by_ipnum_v6;

#define LIBNAME LIBPATH"/libGeoIP.so.1"

static int __attribute__((__format__(printf, 2, 3)))
safe_asprintf(char **strp, const char *fmt, ...)
{
	int ret;
	va_list args;

	va_start(args, fmt);
	ret = vasprintf(&(*strp), fmt, args);
	va_end(args);
	if (ret < 0) {
		fprintf(stderr, "Memory allocation failure\n");
		exit(1);
	}
	return ret;
}

int geo_setup(struct ipcalc_control *ctl)
{
	static int ret = 0;
	static char err[256] = {0};

	if (ctl->ld != NULL || ret != 0) {
		if (!ctl->beSilent && err[0] != 0) {
	    		fprintf(stderr, "%s", err);
		}
		return ret;
	}

	ctl->ld = dlopen(LIBNAME, RTLD_LAZY);
	if (ctl->ld == NULL) {
		char *errmsg;

		errmsg = dlerror();
		if (errmsg)
			snprintf(err, sizeof(err), "ipcalc: could not open %s: %s\n", LIBNAME, errmsg);
		else
			snprintf(err, sizeof(err), "ipcalc: could not open %s\n", LIBNAME);
		ret = -1;
		goto exit;
	}

	p_GeoIP_setup_dbfilename = dlsym(ctl->ld, "_GeoIP_setup_dbfilename");

	pGeoIP_open_type = dlsym(ctl->ld, "GeoIP_open_type");
	pGeoIP_country_name_by_id = dlsym(ctl->ld, "GeoIP_country_name_by_id");
	pGeoIP_delete = dlsym(ctl->ld, "GeoIP_delete");
	pGeoIP_record_by_ipnum = dlsym(ctl->ld, "GeoIP_record_by_ipnum");
	pGeoIP_id_by_ipnum = dlsym(ctl->ld, "GeoIP_id_by_ipnum");
	pGeoIP_id_by_ipnum_v6 = dlsym(ctl->ld, "GeoIP_id_by_ipnum_v6");
	pGeoIP_record_by_ipnum_v6 = dlsym(ctl->ld, "GeoIP_record_by_ipnum_v6");
	pGeoIP_code_by_id = dlsym(ctl->ld, "GeoIP_code_by_id");

	if (pGeoIP_open_type == NULL || pGeoIP_country_name_by_id == NULL ||
	    pGeoIP_delete == NULL || pGeoIP_record_by_ipnum == NULL ||
	    pGeoIP_id_by_ipnum == NULL || pGeoIP_id_by_ipnum_v6 == NULL ||
	    pGeoIP_record_by_ipnum_v6 == NULL) {
		snprintf(err, sizeof(err), "ipcalc: could not find symbols in libGeoIP\n");
	    	ret = -1;
	    	goto exit;
	}

	ret = 0;
 exit:
	return ret;
}

int geo_end(struct ipcalc_control *ctl)
{
	if (ctl->ld)
		return dlclose(ctl->ld);
	return 0;
}

# else

extern void _GeoIP_setup_dbfilename(void);
#  define p_GeoIP_setup_dbfilename _GeoIP_setup_dbfilename
#  define pGeoIP_open_type GeoIP_open_type
#  define pGeoIP_country_name_by_id GeoIP_country_name_by_id
#  define pGeoIP_delete GeoIP_delete
#  define pGeoIP_record_by_ipnum GeoIP_record_by_ipnum
#  define pGeoIP_id_by_ipnum GeoIP_id_by_ipnum
#  define pGeoIP_id_by_ipnum_v6 GeoIP_id_by_ipnum_v6
#  define pGeoIP_record_by_ipnum_v6 GeoIP_record_by_ipnum_v6
#  define pGeoIP_code_by_id GeoIP_code_by_id
# endif

void geo_ipv4_lookup(struct ipcalc_control *ctl, struct in_addr ip,
		     char **country, char **ccode, char **city, char **coord)
{
	GeoIP *gi;
	GeoIPRecord *gir;
	int country_id;
	const char *p;

	if (geo_setup(ctl) != 0)
		return;

	ip.s_addr = ntohl(ip.s_addr);

	p_GeoIP_setup_dbfilename();

	gi = pGeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		country_id = pGeoIP_id_by_ipnum(gi, ip.s_addr);
		if (country_id < 0) {
			return;
		}
		p = pGeoIP_country_name_by_id(gi, country_id);
		if (p)
			*country = safe_strdup(p);

		p = pGeoIP_code_by_id(country_id);
		if (p)
			*ccode = safe_strdup(p);

		pGeoIP_delete(gi);
	}

	gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV1, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		gir = pGeoIP_record_by_ipnum(gi, ip.s_addr);

		if (gir && gir->city)
			*city = safe_strdup(gir->city);

		if (gir && gir->longitude != 0 && gir->longitude != 0)
			safe_asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

		pGeoIP_delete(gi);
	} else {
		gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV0, GEOIP_STANDARD | GEOIP_SILENCE);
		if (gi != NULL) {
			gi->charset = GEOIP_CHARSET_UTF8;

			gir = pGeoIP_record_by_ipnum(gi, ip.s_addr);

			if (gir && gir->city)
				*city = safe_strdup(gir->city);

			if (gir && gir->longitude != 0 && gir->longitude != 0)
				safe_asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

			pGeoIP_delete(gi);
		}
	}

	return;
}

void geo_ipv6_lookup(struct ipcalc_control *ctl, struct in6_addr *ip,
		     char **country, char **ccode, char **city, char **coord)
{
	GeoIP *gi;
	GeoIPRecord *gir;
	int country_id;
	const char *p;

	if (geo_setup(ctl) != 0)
		return;

	p_GeoIP_setup_dbfilename();

	gi = pGeoIP_open_type(GEOIP_COUNTRY_EDITION_V6, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		country_id = pGeoIP_id_by_ipnum_v6(gi, (geoipv6_t)*ip);
		if (country_id < 0) {
			return;
		}
		p = pGeoIP_country_name_by_id(gi, country_id);
		if (p)
			*country = safe_strdup(p);

		p = pGeoIP_code_by_id(country_id);
		if (p)
			*ccode = safe_strdup(p);

		pGeoIP_delete(gi);
	}

	gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV1_V6, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		gir = pGeoIP_record_by_ipnum_v6(gi, (geoipv6_t)*ip);

		if (gir && gir->city)
			*city = safe_strdup(gir->city);

		if (gir && gir->longitude != 0 && gir->longitude != 0)
			safe_asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

		pGeoIP_delete(gi);
	} else {
		gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV0_V6, GEOIP_STANDARD | GEOIP_SILENCE);
		if (gi != NULL) {
			gi->charset = GEOIP_CHARSET_UTF8;

			gir = pGeoIP_record_by_ipnum_v6(gi, (geoipv6_t)*ip);

			if (gir && gir->city)
				*city = safe_strdup(gir->city);

			if (gir && gir->longitude != 0 && gir->longitude != 0)
				safe_asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

			pGeoIP_delete(gi);
		}
	}

	return;
}

#endif
