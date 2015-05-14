#ifdef USE_GEOIP
void geo_ipv4_lookup(struct in_addr ip, char **country, char **city, char  **coord);
void geo_ipv6_lookup(struct in6_addr *ip, char **country, char **city, char **coord);
#else
# define geo_ipv4_lookup(x,y,z,w)
# define geo_ipv6_lookup(x,y,z, w)
#endif

extern int beSilent;
