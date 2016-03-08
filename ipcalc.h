#ifdef USE_GEOIP
void geo_ipv4_lookup(struct in_addr ip, char **country, char **ccode, char **city, char  **coord);
void geo_ipv6_lookup(struct in6_addr *ip, char **country, char **ccode, char **city, char **coord);
int geo_setup(void);
#else
# define geo_ipv4_lookup(x,y,z,w,a)
# define geo_ipv6_lookup(x,y,z,w,a)
# define geo_setup() -1
#endif

char *calc_reverse_dns4(struct in_addr ip, unsigned prefix, struct in_addr net, struct in_addr bcast);
char *calc_reverse_dns6(struct in6_addr *ip, unsigned prefix);

extern int beSilent;
