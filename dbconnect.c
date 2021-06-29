#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include "miscs.h"
#include "dbconnect.h"

int maria_init(struct maria *db, const char *dbname)
{
	int retv = 0;
	struct passwd *pwd;

	db->stmt = malloc(1024);
	if (!db->stmt) {
		elog("Out of Memory.\n");
		return -100;
	}
	db->dbh = mysql_init(NULL);
	if (!db->dbh) {
		elog("maria: Cannot initialize connection handler.\n");
		retv = -1;
		goto exit_10;
	}
	pwd = getpwuid(getuid());
	db->dbh = mysql_real_connect(db->dbh, NULL, pwd->pw_name, NULL, dbname,
			0, NULL, 0);
	if (!db->dbh) {
		elog("maria: Cannot connect to database.\n");
		retv = -2;
		goto exit_20;
	}
	return retv;

exit_20:
	mysql_close(db->dbh);
exit_10:
	free(db->stmt);
	return retv;
}

void maria_exit(struct maria *db)
{
	mysql_close(db->dbh);
	free(db->stmt);
}

int maria_query(struct maria *db, const char *fmt, ...)
{
	int retv;
	va_list ap;

	va_start(ap, fmt);
	vsprintf(db->stmt, fmt, ap);
	va_end(ap);
	retv = mysql_query(db->dbh, db->stmt);
	if (retv)
		elog("DB Statement '%s' failed: %s\n", db->stmt,
				mysql_error(db->dbh));
	return retv;
}
