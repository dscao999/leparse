#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include "miscs.h"
#include "dbconnect.h"

int maria_init(struct maria *db, const char *dbname, const char *usrnam)
{
	int retv = 0;
	MYSQL *sqlhand;

	db->stmt = malloc(1024+sizeof(MYSQL));
	if (unlikely(!db->stmt)) {
		elog("Out of Memory.\n");
		return -100;
	}
	db->dbh = (MYSQL *)(db->stmt + 1024);
	db->dbh = mysql_init(db->dbh);
	if (unlikely(!db->dbh)) {
		elog("maria: Cannot initialize connection handler.\n");
		retv = -1;
		goto exit_10;
	}
	sqlhand = mysql_real_connect(db->dbh, NULL, usrnam, NULL, dbname,
			0, NULL, 0);
	if (unlikely(!sqlhand)) {
		elog("maria: Cannot connect to database: %s\n", 
				mysql_error(db->dbh));
		retv = -2;
		goto exit_20;
	}
	strcpy(db->database, dbname);
	strcpy(db->username, usrnam);
	db->res = NULL;
	return retv;

exit_20:
	mysql_close(db->dbh);
exit_10:
	free(db->stmt);
	return retv;
}

void maria_exit(struct maria *db)
{
	if (db->res) {
		mysql_free_result(db->res);
		db->res = NULL;
	}
	mysql_close(db->dbh);
	free(db->stmt);
}

static int maria_reconnect(struct maria *db)
{
	int retv;
	MYSQL *sqlhand;

	retv = 0;
	if (db->res) {
		mysql_free_result(db->res);
		db->res = NULL;
	}
	mysql_close(db->dbh);

	sqlhand = mysql_init(db->dbh);
	if (unlikely(!sqlhand)) {
		elog("maria: Cannot initialize connection handler.\n");
		retv = -1;
		return retv;
	}
	sqlhand = mysql_real_connect(db->dbh, NULL, db->username, NULL,
			db->database, 0, NULL, 0);
	if (unlikely(!sqlhand)) {
		elog("maria: Cannot connect to database: %s\n", 
				mysql_error(db->dbh));
		mysql_close(db->dbh);
		retv = -2;
	}
	return retv;
}

int maria_query(struct maria *db, int fetch, const char *fmt, ...)
{
	int retv;
	va_list ap;

	va_start(ap, fmt);
	vsprintf(db->stmt, fmt, ap);
	va_end(ap);

	maria_free_result(db);
	retv = mysql_query(db->dbh, db->stmt);
	if (unlikely(retv)) {
		if (unlikely(retv != 0) && verbose)
			elog("DB Statement \"%s\" failed: %s\n", db->stmt,
					mysql_error(db->dbh));
		retv = maria_reconnect(db);
		if (unlikely(retv != 0)) {
			elog("DB Reconnection failed\n");
			return retv;
		}
	}
	if (!fetch)
		return retv;

	db->res = mysql_store_result(db->dbh);
	if (unlikely(!db->res)) {
		elog("Cannto store the query '%s' result set: %s\n",
				db->stmt, mysql_error(db->dbh));
		retv = -5;
	}
	return retv;
}
