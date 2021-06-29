#ifndef DBCONNECT_DSCAO__
#define DBCONNECT_DSCAO__
#include <stdarg.h>
#include <mariadb/mysql.h>

struct maria {
	MYSQL *dbh;
	char *stmt;
};

int maria_init(struct maria *db, const char *dbname);
void maria_exit(struct maria *db);

int maria_query(struct maria *db, const char *fmt, ...);

#endif /* DBCONNECT_DSCAO__ */
