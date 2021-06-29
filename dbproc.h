#ifndef DBPROC_DSCAO__
#define DBPROC_DSCAO__

struct lease_info {
	char mac[24];
	char ip [64];
	time_t tm, stm;
	int leave;
};

int dbproc(const struct lease_info *inf);
#endif  /* DBPROC_DSCAO__ */
