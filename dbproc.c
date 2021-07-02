#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <linux/random.h>
#include <errno.h>
#include "miscs.h"
#include "dbproc.h"
#include "dbconnect.h"

static int update_citizen(struct maria *db, const struct lease_info *inf,
		int mac2)
{
	int retv = 0;

	if (!mac2) {
		retv = maria_query(db, 0, "update citizen set last = '%lu', " \
				" ip = '%s' where mac = '%s'",
				inf->tm, inf->ip, inf->mac);
	} else {
		retv = maria_query(db, 0, "update citizen set last = '%lu', " \
				"ip2 = '%s' where mac2 = '%s'",
				inf->tm, inf->ip, inf->mac);
	}
	if (retv)
		elog("Cannot update citizen.\n");
			
	return retv;
}

int dbproc(const struct lease_info *inf)
{
	struct maria *db;
	int retv = 0, idx;
	int nfields, found, mac2;
	MYSQL_ROW row;
	time_t tm;
	char *passwd, *hostname;
	unsigned char *passwd_new, *curp;
	FILE *rndh;

	db = malloc(sizeof(struct maria)+64);
	if (!db) {
		elog("Out of Memory.\n");
		retv = -1;
		return retv;
	}
	passwd = (char *)(db + 1);
	hostname = passwd + 24;
	passwd_new = (unsigned char *)(hostname + 16);
	retv = maria_init(db, "lidm");
	if (retv != 0) {
		elog("Cannot initialize db connection to %s\n", "lidm");
		retv = -1;
		goto exit_10;
	}
	printf("DB Connected.\n");
	retv = maria_query(db, 1, "select count(*) from barbarian where " \
			"mac = '%s'", inf->mac);
	if (retv) {
		retv = -3;
		goto exit_20;
	}
	found = 0;
	row = mysql_fetch_row(db->res);
	if (row && row[0])
		found = atoi(row[0]);
	else
		elog("Internal logic error: no result from count(*)\n");
	maria_free_result(db);
	if (found)
		goto exit_20;

	retv = maria_query(db, 1, "select mac, mac2, last from citizen where " \
			"mac = '%s' or mac2 = '%s'", inf->mac, inf->mac);
	if (retv) {
		retv = -6;
		goto exit_20;
	}
	nfields = mysql_num_fields(db->res);
	assert(nfields == 3);
	found = 0;
	row = mysql_fetch_row(db->res);
	if (row) {
		tm = atoll(row[2]);
		if (tm < inf->tm) {
			mac2 = 0;
			if (row[1] && strcmp(row[1], inf->mac) == 0)
				mac2 = 1;
			update_citizen(db, inf, mac2);
		}
		row = mysql_fetch_row(db->res);
		if (row)
			elog("Internal logic error: dublicate citizen records.\n");
		maria_free_result(db);
		goto exit_20;
	}
	maria_free_result(db);
	retv = maria_query(db, 0, "insert into citizen (mac, ip, birth, last) "\
			"values ('%s', '%s', %lu, %lu)", inf->mac, inf->ip,
			inf->tm, inf->tm);
	if (retv) {
		retv = -5;
		goto exit_20;
	}
	retv = maria_query(db, 1, "select hostname, password, hostseq from " \
			"citizen where mac = '%s'", inf->mac);
	if (retv) {
		retv = -6;
		goto exit_20;
	}
	row = mysql_fetch_row(db->res);
	if (!row) {
		elog("Internal logic error, no default password.\n");
		retv = -7;
		goto exit_20;
	}
	sprintf(hostname, "%s%04d", row[0], atoi(row[2]));
	strcpy(passwd, row[1]);
	maria_free_result(db);
	rndh = fopen("/dev/urandom", "rb");
	if (!rndh) {
		elog("Cannot open /dev/urandom: %s\n", strerror(errno));
		retv = -8;
		goto exit_20;
	}
	for (idx = 0, curp = passwd_new; idx < 10; idx++, curp++) {
		do
			fread(curp, 1, 1, rndh);
		while (*curp < 0x21 || *curp > 0x7e);

	};
	*curp = 0;
	fclose(rndh);
	printf("hostname: %s, password: '%s'\n", hostname, passwd_new);
exit_20:
	maria_exit(db);
exit_10:
	free(db);
	return retv;
}
