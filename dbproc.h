#ifndef DBPROC_DSCAO__
#define DBPROC_DSCAO__

struct lease_info {
	char mac[24];
	char ip [64];
	time_t tm, stm;
	int leave;
};

struct os_info {
	char uuid[36];
	char serial[24];
	char product[24];
	char hostname[16];
	char user[12];
	char passwd[24];
	char passwd_new[24];
	const char *ip;
};

int dbproc(const struct lease_info *inf);
#endif  /* DBPROC_DSCAO__ */
