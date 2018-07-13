#define _GNU_SOURCE


#include <maxminddb.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipcalc.h"

#ifdef USE_MAXMIND

#ifndef MAXMINDDB_LOCATION_COUNTRY
#define MAXMINDDB_LOCATION_COUNTRY "/usr/share/GeoIP/GeoLite2-Country.mmdb"
#endif

#ifndef MAXMINDDB_LOCATION_CITY
#define MAXMINDDB_LOCATION_CITY "/usr/share/GeoIP/GeoLite2-City.mmdb"
#endif

void process_result_from_mmdb_lookup(MMDB_entry_data_s *entry_data, int status, char **output)
{
    if (MMDB_SUCCESS == status) {
        if (entry_data->has_data) {
            if (entry_data->type == MMDB_DATA_TYPE_UTF8_STRING) {
                *output = (char *) calloc(entry_data->data_size + 1, sizeof(char));
                if (NULL != *output) {
                    memcpy(*output, entry_data->utf8_string, entry_data->data_size);
                } else {
                    fprintf(stderr, "Memory allocation failure line %d\n", __LINE__);
                }
            }
        }
    }
    /* Else fail silently */
}

void mmdb_ip_lookup(const char *ip, char **country, char **ccode, char **city, char **coord)
{
    MMDB_s mmdb;
    MMDB_entry_data_s entry_data;
    int gai_error, mmdb_error, status, coordinates=0;
    double latitude, longitude;

    /* Open the system maxmind database with countries */
    status = MMDB_open(MAXMINDDB_LOCATION_COUNTRY, MMDB_MODE_MMAP, &mmdb);
    if (MMDB_SUCCESS == status) {
        /* Lookup IP address in the database */
        MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip, &gai_error, &mmdb_error);
        if (MMDB_SUCCESS == mmdb_error) { 
            /* If the lookup was successfull and an entry was found */
            if (result.found_entry) {
                memset(&entry_data, 0, sizeof(MMDB_entry_data_s));
                /* Travel the path in the tree like structure of the MMDB and store the value if found */
                status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
                process_result_from_mmdb_lookup(&entry_data, status, country);
                memset(&entry_data, 0, sizeof(MMDB_entry_data_s));
                status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
                process_result_from_mmdb_lookup(&entry_data, status, ccode);
            }
        }
        /* Else fail silently */
        MMDB_close(&mmdb);
    }
    /* Else fail silently */

    /* Open the system maxmind database with cities - which actually does not contain names of the cities */
    status = MMDB_open(MAXMINDDB_LOCATION_CITY, MMDB_MODE_MMAP, &mmdb);
    if (MMDB_SUCCESS == status) {
        /* Lookup IP address in the database */
        MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip, &gai_error, &mmdb_error);
        if (MMDB_SUCCESS == mmdb_error) { 
            /* If the lookup was successfull and an entry was found */
            if (result.found_entry) {
                memset(&entry_data, 0, sizeof(MMDB_entry_data_s));
                // TODO: city is not available in the free database
                status = MMDB_get_value(&result.entry, &entry_data, "location", "latitude", NULL);
                if (MMDB_SUCCESS == status) {
                    if (entry_data.has_data) {
                        if (entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
                            latitude = entry_data.double_value;
                            ++coordinates;
                        }
                    }
                }
                status = MMDB_get_value(&result.entry, &entry_data, "location", "longitude", NULL);
                if (MMDB_SUCCESS == status) {
                    if (entry_data.has_data) {
                        if (entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
                            longitude = entry_data.double_value;
                            ++coordinates;
                        }
                    }
                }
                if (coordinates == 2) {
                    safe_asprintf(coord, "Latitude: %f, longitude: %f", latitude, longitude);
                }
            }
        }
        /* Else fail silently */
        MMDB_close(&mmdb);
    }
    /* Else fail silently */
}

#endif
