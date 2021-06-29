#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include "miscs.h"
#include "dbproc.h"
#include "dbconnect.h"

static int update_citizen(struct maria *db, const struct lease_info *inf,
		int mac2)
{
	int retv = 0;

	if (!mac2) {
		retv = maria_query(db, "update citizen set last = '%lu', " \
				" ip = '%s' where mac = '%s'",
				inf->tm, inf->ip, inf->mac);
	} else {
		retv = maria_query(db, "update citizen set last = '%lu', " \
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
	int retv = 0;
	int nfields, found, mac2;
	MYSQL_RES *res;
	MYSQL_ROW row;
	time_t tm;

	db = malloc(sizeof(struct maria));
	if (!db) {
		elog("Out of Memory.\n");
		retv = -1;
		return retv;
	}
	retv = maria_init(db, "lidm");
	if (retv != 0) {
		elog("Cannot initialize db connection to %s\n", "lidm");
		retv = -1;
		goto exit_10;
	}
	printf("DB Connected.\n");
	retv = maria_query(db, "select count(*) from barbarian where " \
			"mac = '%s'", inf->mac);
	if (retv) {
		retv = -3;
		goto exit_20;
	}
	res = mysql_store_result(db->dbh);
	if (!res) {
		elog("Cannot get DB result: %s\n", mysql_error(db->dbh));
		retv = -4;
		goto exit_20;
	}
	nfields = mysql_num_fields(res);
	assert(nfields == 1);
	found = 0;
	row = mysql_fetch_row(res);
	if (row && row[0])
		found = atoi(row[0]);
	else
		elog("Internal logic error: no result from count(*)\n");
	mysql_free_result(res);
	if (found)
		goto exit_20;

	retv = maria_query(db, "select mac, mac2, last from citizen where " \
			"mac = '%s' or mac2 = '%s'", inf->mac, inf->mac);
	if (retv) {
		retv = -5;
		goto exit_20;
	}
	res = mysql_store_result(db->dbh);
	if (!res) {
		elog("Cannot get DB result: %s\n", mysql_error(db->dbh));
		retv = -6;
		goto exit_20;
	}
	nfields = mysql_num_fields(res);
	assert(nfields == 3);
	found = 0;
	row = mysql_fetch_row(res);
	if (row) {
		tm = atoll(row[2]);
		if (tm < inf->tm) {
			mac2 = 0;
			if (row[1] && strcmp(row[1], inf->mac) == 0)
				mac2 = 1;
			update_citizen(db, inf, mac2);
		}
		mysql_free_result(res);
		goto exit_20;
	}
	row = mysql_fetch_row(res);
	if (row)
		elog("Internal logic error: dublicate citizen records.\n");
	mysql_free_result(res);

	retv = maria_query(db, "insert into citizen (mac, ip, birth, last) " \
			"values ('%s', '%s', %lu, %lu)", inf->mac, inf->ip,
			inf->tm, inf->tm);
	if (retv) {
		retv = -5;
		goto exit_20;
	}

exit_20:
	maria_exit(db);
exit_10:
	free(db);
	return retv;
}
