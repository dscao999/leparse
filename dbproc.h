#ifndef DBPROC_DSCAO__
#define DBPROC_DSCAO__

struct lease_info {
	char mac[24];
	char ip[64];
	unsigned long hostid;
	time_t tm;
	int leave;
	int semset;
};

struct os_info {
	char uuid[40];
	char serial[24];
	char hostname[16];
	char user[12];
	char passwd[24];
	char passwd_new[24];
	const char *ip;
};

static inline void dump_lease_info(const struct lease_info *linfo)
{
	elog("Timestamp: %ld Mac: %s IP: %s Operation: %s\n", linfo->tm,
			linfo->mac, linfo->ip, (linfo->leave)? "Leave":"Lease");
}

extern int verbose;

int dbproc(const struct lease_info *inf, const char *usrnam);
int delete_null_uuid(const char *usrnam);
#endif  /* DBPROC_DSCAO__ */
