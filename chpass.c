#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include "miscs.h"
#include "dbconnect.h"
#include "random_passwd.h"
#include "pipe_execution.h"

int main(int argc, char *argv[])
{
	int c, fin, reslen, retv;
	const char *uuid = NULL, *password = NULL;
	char passwd_new[16], admin[12], *res, *cmd, *input;
	struct passwd *uent;
	extern char *optarg;
	extern int optind, opterr, optopt;

	fin = 0;
	do {
		c = getopt(argc, argv, ":p:");
		switch(c) {
		case '?':
			elog("Unknown option: %c\n", (char)optopt);
			break;
		case ':':
			elog("Missing arguments for %c\n", (char)optopt);
			break;
		case 'p':
			password = optarg;
			break;
		case -1:
			fin = 1;
			break;
		default:
			assert(0);
		}
	} while (fin == 0);
	if (optind >= argc) {
		elog("An UUID of the client must be specified.\n");
		return 1;
	}
	uuid = argv[optind];
	if (!password) {
		random_passwd(passwd_new);
		password = passwd_new;
		printf("New Password: %s\n", passwd_new);
	}
	uent = getpwuid(getuid());
	if (unlikely(!uent)) {
		elog("getpwuid failed: %s\n", strerror(errno));
		return 2;
	}

	struct maria dbc;
	MYSQL_ROW row;
	char ip[48];
	time_t last, curtm;

	retv = maria_init(&dbc, "lidm", uent->pw_name);
	if (unlikely(retv != 0)) {
		elog("Cannot connect to database.\n");
		return retv;
	}
	retv = maria_query(&dbc, 1, "select ip, admin, last from citizen where " \
			"uuid = '%s'", uuid);
	if (unlikely(retv)) {
		elog("search for %s failed.\n", uuid);
		goto exit_10;
	}
	row = mysql_fetch_row(dbc.res);
	if (unlikely(!row)) {
		elog("no such %s uuid exists.\n", uuid);
		goto exit_10;
	}
	strcpy(ip, row[0]);
	strcpy(admin, row[1]);
	last = atoll(row[2]);
	maria_free_result(&dbc);
	if (last == 0) {
		elog("%s is offline now.\n", uuid);
		retv = 1;
		goto exit_10;
	} else {
		curtm = time(NULL);
		printf("%s is online at %lu seconds before.\n",
				uuid, curtm - last);
	}

	reslen = 1024;
	res = malloc(reslen+1024+64);
	cmd = res + reslen;
	input = cmd + 1024;
	sprintf(cmd, "ssh -l root %s passwd %s", ip, admin);
	strcpy(input, password);
	strcat(input, "\n");
	strcat(input, password);
	strcat(input, "\n");
	retv = maria_query(&dbc, 0, "start transaction");
	if (unlikely(retv)) {
		elog("Cannot start DB transaction.\n");
		goto exit_20;
	}
	retv = maria_query(&dbc, 0, "update citizen set password = '%s' where "\
			"uuid = '%s'", password, uuid);
	if (unlikely(retv)) {
		elog("Cannot update password for %s\n", uuid);
		goto exit_20;
	}
	retv = pipe_execute(res, reslen, cmd, input);
	if (unlikely(retv)) {
		elog("Cannot change passwod for %s\n", uuid);
		goto exit_20;
	}
	retv = maria_query(&dbc, 0, "commit release");
	if (unlikely(retv))
		elog("Fatal Error, Cannot commit password change.\n");

exit_20:
	free(res);
exit_10:
	maria_exit(&dbc);
	return retv;
}
