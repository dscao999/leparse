#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/random.h>
#include <errno.h>
#include <signal.h>
#include "miscs.h"
#include "dbproc.h"
#include "dbconnect.h"

static int scp_execute(char *res, int reslen, const char *ip,
		const char *fname)
{
	struct stat mst;
	int sysret, idx, pfdin[2], fdout, fdin;
	int retv = -1, numb;
	char *cmdbuf, **scparg, *curchr;
	pid_t scpid;
	static const char *fmt = "scp -o BatchMode=yes %s root@%s:";

	sysret = stat(fname, &mst);
	if (sysret == -1) {
		fprintf(stderr, "No such file %s: %s\n", fname,
				strerror(errno));
		return -errno;
	}
	cmdbuf = malloc(512+sizeof(char *)*6);
	scparg = (char **)(cmdbuf + 512);
	sprintf(cmdbuf, fmt, fname, ip);
	idx = 0;
	curchr = strtok(cmdbuf, " ");
	while (curchr && idx < 5) {
		scparg[idx++] = curchr;
		curchr = strtok(NULL, " ");
	}
	scparg[idx] = NULL;
	sysret = pipe(pfdin);
	if (sysret == -1) {
		fprintf(stderr, "pipe in failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_10;
	}
	scpid = fork();
	if (scpid == -1) {
		fprintf(stderr, "fork failed: %s\n", strerror(errno));
		goto exit_20;
	}
	if (scpid == 0) {
		fdout = pfdin[1];
		close(pfdin[0]);
		fclose(stdout);
		fclose(stderr);
		stdout = fdopen(dup(fdout), "w");
		stderr = fdopen(dup(fdout), "w");
		close(fdout);
		sysret = execvp("/usr/bin/scp", scparg);
		if (sysret == -1)
			fprintf(stderr, "exec failed %s\n", strerror(errno));
		exit(errno);
	}
	sigset_t sset;
	sigemptyset(&sset);
	sigaddset(&sset, SIGCHLD);
	sysret = waitpid(scpid, &retv, 0);
	fdin = pfdin[0];
	numb = read(fdin, res, reslen);
	res[numb] = 0;
	printf("scp code: %d\n", retv);
	printf("scp result: %s\n", res);

exit_20:
	close(pfdin[0]);
	close(pfdin[1]);
exit_10:
	free(cmdbuf);
	return retv;
}

static int ssh_probe(char *res, int reslen, const struct os_info *oinf)
{
	int pfdin[2], pfdout[2], idx, sysret, retv;
	int fdin, fdout, numb;
	char *cmdbuf, *curchr;
	char **ssharg;
	pid_t sshpid;
	char passwd[16];
	static const char *fmt = "sshpass -p %s ssh -l %s %s sudo -S " \
			  "lios_lock_probe.py --hostname %s --password '%s'";

	*res = 0;
	cmdbuf = malloc(512+sizeof(char *)*18);
	ssharg = (char **)(cmdbuf+512);

	retv = pipe(pfdin);
	if (retv == -1) {
		fprintf(stderr, "pipe failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_10;
	}
	sysret = pipe(pfdout);
	if (sysret == -1) {
		fprintf(stderr, "pipe out failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_20;
	}
	sprintf(cmdbuf, fmt, oinf->passwd, oinf->user, oinf->ip,
			oinf->hostname, oinf->passwd_new);
	idx = 0;
	curchr = strtok(cmdbuf, " ");
	while (curchr && idx < 17) {
		ssharg[idx++] = curchr;
		curchr = strtok(NULL, " ");
	}
	ssharg[idx] = NULL;
	strcpy(passwd, oinf->passwd);
	strcat(passwd, "\n");
	sshpid = fork();
	if (sshpid == -1) {
		fprintf(stderr, "fork failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_30;
	}
	sigset_t sset;
	sigemptyset(&sset);
	sigaddset(&sset, SIGCHLD);
	if (sshpid == 0) {
		close(pfdin[0]);
		fdout = pfdin[1];
		close(pfdout[1]);
		fdin = pfdout[0];
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);
		stdin = fdopen(dup(fdin), "r");
		stdout = fdopen(dup(fdout), "w");
		stderr = fdopen(dup(fdout), "w");
		close(fdin);
		close(fdout);
		sysret = execv("/usr/bin/sshpass", ssharg);
		if (sysret == -1)
			fprintf(stderr, "exec failed: %s\n", strerror(errno));
		exit(1);
	}
	fdout = pfdout[1];
	fdin = pfdin[0];
	numb = write(fdout, passwd, strlen(passwd));
	if (numb == -1)
		fprintf(stdout, "Write password through pipe failed: %s\n",
				strerror(errno));
	sysret = waitpid(sshpid, &retv, 0);
	numb = read(fdin, res, reslen);
	*(res+numb) = 0;
	if (retv != 0)
		fprintf(stderr, "ssh probe failed: %s\n", res);

exit_30:
	close(pfdout[0]);
	close(pfdout[1]);
exit_20:
	close(pfdin[0]);
	close(pfdin[1]);
exit_10:
	free(cmdbuf);
	return retv;
}

static int update_citizen(struct maria *db, const struct lease_info *inf,
		int mac2, const char *uuid)
{
	int retv = 0;
	char *mesg;

	mesg = malloc(1024);
	if (!uuid) {
		retv = scp_execute(mesg, 1024, inf->ip, "../utils/dmi_read/smird");
		return retv;
	}
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
	char *curp;
	FILE *rndh;
	const char *uuid;
	struct os_info *oinf;
	char *buf;

	db = malloc(sizeof(struct maria)+sizeof(struct os_info)+1024);
	if (!db) {
		elog("Out of Memory.\n");
		retv = -1;
		return retv;
	}
	oinf = (struct os_info *)(db + 1);
	oinf->ip = inf->ip;
	buf = (char *)(oinf + 1);

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

	retv = maria_query(db, 1, "select mac, mac2, last, uuid from citizen " \
		       	"where mac = '%s' or mac2 = '%s'", inf->mac, inf->mac);
	if (retv) {
		retv = -6;
		goto exit_20;
	}
	nfields = mysql_num_fields(db->res);
	assert(nfields == 4);
	found = 0;
	row = mysql_fetch_row(db->res);
	if (row) {
		tm = atoll(row[2]);
		uuid = row[3];
		if (tm < inf->tm) {
			mac2 = 0;
			if (row[1] && strcmp(row[1], inf->mac) == 0)
				mac2 = 1;
			update_citizen(db, inf, mac2, uuid);
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
	retv = maria_query(db, 1, "select hostname, password, hostseq, admin "\
		       	"from citizen where mac = '%s'", inf->mac);
	if (retv) {
		retv = -6;
		goto exit_20;
	}
	nfields = mysql_num_fields(db->res);
	assert(nfields == 4);
	row = mysql_fetch_row(db->res);
	if (!row) {
		elog("Internal logic error, no default password.\n");
		retv = -7;
		goto exit_20;
	}
	sprintf(oinf->hostname, "%s%04d", row[0], atoi(row[2]));
	strcpy(oinf->passwd, row[1]);
	strcpy(oinf->user, row[3]);
	maria_free_result(db);
	rndh = fopen("/dev/urandom", "rb");
	if (!rndh) {
		elog("Cannot open /dev/urandom: %s\n", strerror(errno));
		retv = -8;
		goto exit_20;
	}
	for (idx = 0, curp = oinf->passwd_new; idx < 10; idx++, curp++) {
		do
			fread(curp, 1, 1, rndh);
		while (*curp < 0x21 || *curp > 0x7e || *curp == '\'' || *curp == '"');

	};
	*curp = 0;
	fclose(rndh);
	printf("new hostname: %s, new password: '%s'\n", oinf->hostname,
			oinf->passwd_new);
	retv = ssh_probe(buf, 1024, oinf);

exit_20:
	maria_exit(db);
exit_10:
	free(db);
	return retv;
}
