#ifndef DBCONNECT_DSCAO__
#define DBCONNECT_DSCAO__
#include <stdarg.h>
#include <mariadb/mysql.h>

struct maria {
	MYSQL *dbh;
	char *stmt;
	MYSQL_RES *res;
};

int maria_init(struct maria *db, const char *dbname);
void maria_exit(struct maria *db);

int maria_query(struct maria *db, int fetch, const char *fmt, ...);

static inline void maria_free_result(struct maria *db)
{
	if (db->res) {
		mysql_free_result(db->res);
		db->res = NULL;
	}
}

#endif /* DBCONNECT_DSCAO__ */
