#ifndef DBCONNECT_DSCAO__
#define DBCONNECT_DSCAO__
#include <stdarg.h>
#include <mariadb/mysql.h>

struct maria {
	MYSQL *dbh;
	char *stmt;
	MYSQL_RES *res;
};
#define TRANSACT	"start transaction"
#define COMMIT		"commit release"

int maria_init(struct maria *db, const char *dbname, const char *usrnam);
void maria_exit(struct maria *db);

int maria_query(struct maria *db, int fetch, const char *fmt, ...);

static inline void maria_free_result(struct maria *db)
{
	if (db->res) {
		mysql_free_result(db->res);
		db->res = NULL;
	}
}

static inline int maria_transact(struct maria *db)
{
	return maria_query(db, 0, TRANSACT);
}
static inline int maria_commit(struct maria *db)
{
	return maria_query(db, 0, COMMIT);
}
static inline int maria_rollback(struct maria *db)
{
	return mysql_rollback(db->dbh);
}
static inline const char * maria_error(struct maria *db)
{
	return mysql_error(db->dbh);
}

#endif /* DBCONNECT_DSCAO__ */
