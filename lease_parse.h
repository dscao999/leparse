#ifndef DHCP_LEASE_PARSE_DSCAO__
#define DHCP_LEASE_PARSE_DSCAO__

struct dhclient_lease {
	unsigned int recsiz;
	unsigned int curpos;
	char rec[1];
};

struct dhclient_lease * dhclient_init(unsigned int buflen);
void dhclient_exit(struct dhclient_lease *lebuf);
int dhclient_lease_parse(FILE *fin, struct dhclient_lease *lebuf);

#endif /* DHCP_LEASE_PARSE_DSCAO__ */
