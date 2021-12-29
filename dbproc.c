#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/random.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include "miscs.h"
#include "pipe_execution.h"
#include "dbproc.h"
#include "dbconnect.h"
#include "random_passwd.h"

static const int CMDLEN = 512;
static const int MSGLEN = 2048;
static const int INPLEN = 128;

static int fetch_osinfo(struct os_info *oinf, const char *ip,
		char *resbuf, int reslen)
{
	int retv, count, len;
	char *curp;
	static const char *splits = ":\n";

	retv = ssh_execute(resbuf, reslen, ip, "smird", NULL, 0);
	len = strlen(resbuf);
	if (unlikely(retv != 0 || len == 0)) {
		elog("Cannot fetch os info using \"smird\". retv:%d, len:%d\n",\
				retv, len);
		if (len == 0)
			retv = 71;
		return retv;
	}
	count = 0;
	curp = strtok(resbuf, splits);
	while (curp && count < 2) {
		if (strcmp(curp, "UUID") == 0) {
			curp = strtok(NULL, splits);
			strcpy(oinf->uuid, curp+1);
			count += 1;
		} else if (strcmp(curp, "Serial Number") == 0) {
			curp = strtok(NULL, splits);
			strcpy(oinf->serial, curp+1);
			count += 1;
		}
		curp = strtok(NULL, ":\n");
	}
	return retv;
}

static inline int ssh_remove_stale_ip(const char *ip)
{
	char *cmd, *res;
	int retv;
	static const char *fmt = "ssh-keygen -R %s";

	cmd = malloc(CMDLEN+MSGLEN);
	if (!cmd) {
		elog("Out of Memory in %s\n", __func__);
		exit(100);
	}
	res = cmd + CMDLEN;
	sprintf(cmd, fmt, ip);
	retv = pipe_execute(res, MSGLEN, cmd, NULL);
	if (verbose)
		elog("%s\n", res);
	free(cmd);
	return retv;
}

static int ssh_probe(char *res, int reslen, const struct os_info *oinf)
{
	int retv;
	char *cmdbuf, *msgbuf;
	static const char *fmt = "lios_lock_probe.py " \
				  "--hostname %s --password %s --username %s";

	assert(reslen >= CMDLEN+INPLEN+MSGLEN);
	*res = 0;
	cmdbuf = res;
	msgbuf = cmdbuf + CMDLEN+INPLEN;
	sprintf(cmdbuf, fmt, oinf->hostname, oinf->passwd_new, oinf->user);
	retv = ssh_execute(msgbuf, MSGLEN, oinf->ip, cmdbuf, NULL, 0);
	return retv;
}

static const char *host_id_changed = "WARNING: REMOTE HOST IDENTIFICATION HAS" \
				     " CHANGED!";

static int trust_probe(const char *ip)
{
	char *mesg;
	int retv, loop;
	static const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};
	static const char *rcmd = "test true";

	mesg = malloc(MSGLEN);
	if (!mesg) {
		elog("Out of Memory\n");
		exit(100);
	}
	retv = ssh_execute(mesg, MSGLEN, ip, rcmd, NULL, 0);
	if (strstr(mesg, host_id_changed)) {
		ssh_remove_stale_ip(ip);
		retv = ssh_execute(mesg, MSGLEN, ip , rcmd, NULL, 0);
	}
	while (retv != 0 && strstr(mesg, "Permission denied") == NULL &&
			strstr(mesg, "Connection timed out") == NULL) {
		elog("trust probe %s failed: %s\n", ip, mesg);
		op_nanosleep(&itv);
		retv = ssh_execute(mesg, MSGLEN, ip, rcmd, NULL, 0);
		loop += 1;
	}
	if (strstr(mesg, "Connection timed out"))
		retv = 1024;

	free(mesg);
	return retv;
}

static int inctries(struct maria *db, const struct lease_info *inf)
{
	int retv, tries;
	MYSQL_ROW row;

	retv = maria_query(db, 1, "select tries from citizen " \
			"where mac = '%s'", inf->mac);
	if (unlikely(retv != 0)) {
		elog("DB query error for 'tries': %s\n", inf->mac);
		return retv;
	}
	tries = -1;
	row = mysql_fetch_row(db->res);
	if (likely(row))
		tries = atoi(row[0]);
	maria_free_result(db);
	if (unlikely(tries == -1)) {
		elog("Internal Error. Search 'tries' failed: %s\n", inf->mac);
		return 9;
	}
	tries += 1;
	if (tries > 5) {
		elog("Maximu tries to manange %s failed. Move to barbarian\n",
				inf->mac);
		retv = maria_query(db, 0, "delete from citizen " \
				"where mac = '%s'", inf->mac);
		if (unlikely(retv))
			elog("failed to delete unmanaged mac from database\n");
	} else {
		retv = maria_query(db, 0, "update citizen set tries " \
				"= %d where mac = '%s'", tries, inf->mac);
		if (retv)
			elog("update tries failed for '%s'\n", inf->mac);
	}
	if (verbose)
		elog("%d time to manange %s failed.\n",
				tries, inf->mac);
	return retv;
}

static int update_citizen(struct maria *db, const struct lease_info *inf,
		int mac2, const char *uuid, int trusted)
{
	int retv;
	unsigned long tm;

	if (!trusted && !inf->leave) {
		/* mac already in database, trust not build */
		if (uuid) {
			retv = maria_query(db, 0, "delete from citizen " \
					"where mac = '%s' or mac2 = '%s'", \
					inf->mac, inf->mac);
			return retv;
		}

		retv = inctries(db, inf);
		return retv;
	}

	/* mac already in database, trust exists */
	retv = 0;
	tm = inf->tm;
	if (inf->leave)
		tm = 0;
	if (mac2) {
		assert(uuid != NULL);
		retv = maria_query(db, 0, "update citizen set last = %lu, " \
				"ip2 = '%s' where mac2 = '%s'", tm, inf->ip,
				inf->mac);
		if (unlikely(retv))
			elog("Cannot update citizen mac2: %s, ip: %s.\n",
					inf->mac, inf->ip);
	} else if (uuid) {
		retv = maria_query(db, 0, "update citizen set last = %lu, " \
				"ip = '%s' where mac = '%s'", tm, inf->ip,
				inf->mac);
		if (unlikely(retv))
			elog("Cannot update citizen mac: %s, ip: %s.\n",
					inf->mac, inf->ip);
	}

	return retv;
}

static int ssh_copyid(char *res, int reslen, const struct os_info *oinf)
{
	char *cmdline, *mesg, passwd[16], *input;
	int retv;
	static const char *cpyfmt = "sshpass -p %s ssh-copy-id %s@%s";
	static const char *tstfmt = "ssh -l %s %s sudo -S cp -r .ssh /root/";

	assert(reslen >= CMDLEN+INPLEN+MSGLEN);
	retv = trust_probe(oinf->ip);
	if (unlikely(retv == 0))
		return 10000;
	if (unlikely(retv == 1024))
		return retv;

	cmdline = res;
	input = cmdline + CMDLEN;
	mesg = input + INPLEN;
	sprintf(cmdline, cpyfmt, oinf->passwd, oinf->user, oinf->ip);
	retv = pipe_execute(mesg, MSGLEN, cmdline, NULL);
	if (unlikely(retv != 0)) {
		elog("ssh-copy-id failed\n");
		return retv;
	}
	sprintf(cmdline, tstfmt, oinf->user, oinf->ip);
	strcpy(passwd, oinf->passwd);
	strcat(passwd, "\n");
	strcpy(input, passwd);
	strcat(input, passwd);
	strcat(input, passwd);
	retv = pipe_execute(mesg, MSGLEN, cmdline, input);
	if (unlikely(retv != 0))
		elog("ssh-copy-id failed in copying to root\n");
	return retv;
}

static int reset_default_passwd(struct maria *db, const struct lease_info *inf,
		char *cmdbuf, int buflen)
{
	char *inpbuf, *msgbuf, user[16];
	const char *tfile = ".ssh/authorized_keys";
	MYSQL_ROW row;
	int retv = 0, cmdlen, inplen;

	cmdlen = 0;
	inplen = 0;
	assert(buflen >= CMDLEN+INPLEN+MSGLEN);
	inpbuf = cmdbuf + CMDLEN;
	msgbuf = inpbuf + INPLEN;
	retv = maria_query(db, 1, "show columns from citizen");
	if (unlikely(retv != 0)) {
		elog("Get columns failed: %s\n", __func__);
		return retv;
	}
	row = mysql_fetch_row(db->res);
	while (row) {
		if (strcmp(row[0], "admin") == 0) {
			strcpy(user, row[4]);
			cmdlen = sprintf(cmdbuf, "passwd %s", user);
		} else if (strcmp(row[0], "password") == 0) {
			inplen = sprintf(inpbuf, "%s\n%s\n", row[4], row[4]);
		}
		row = mysql_fetch_row(db->res);
	}
	maria_free_result(db);
	if (unlikely(cmdlen == 0 || inplen == 0)) {
		elog("no default user/password found\n");
		return 5;
	}
	retv = ssh_execute(msgbuf, MSGLEN, inf->ip, cmdbuf, inpbuf, 0);
	if (unlikely(retv != 0)) {
		elog("Failed to reset password to default: %s\n", inf->ip);
		return retv;
	}
	sprintf(cmdbuf, "rm -f /home/%s/%s %s", user, tfile, tfile);
	retv = ssh_execute(msgbuf, MSGLEN, inf->ip, cmdbuf, NULL, 0);
	if (unlikely(retv != 0))
		elog("Failed to remove %s in %s\n", tfile, inf->ip);
	return retv;
}

int dbproc(const struct lease_info *inf, int semset, const char *usrnam)
{
	struct maria *db;
	int retv = 0, trusted;
	int found, mac2, buflen, len;
	MYSQL_ROW row;
	time_t tm;
	struct os_info *oinf;
	char *buf, *cmdbuf;
	struct sembuf mop;

	trusted = 0;
	if (!inf->leave) {
		retv = trust_probe(inf->ip);
		if (retv == 1024) {
			elog("client %s unreachable\n", inf->ip);
			return retv;
		}
		trusted = retv == 0;
	}
	buflen = CMDLEN+INPLEN+MSGLEN;
	db = malloc(sizeof(struct maria) + sizeof(struct os_info) + buflen);
	if (unlikely(!db)) {
		elog("Out of Memory.\n");
		retv = -1;
		return retv;
	}
	oinf = (struct os_info *)(db + 1);
	memset(oinf, 0, sizeof(struct os_info));
	oinf->ip = inf->ip;
	buf = (char *)(oinf + 1);
	cmdbuf = buf;

	retv = maria_init(db, "lidm", usrnam);
	if (unlikely(retv != 0)) {
		elog("Cannot initialize db connection to %s\n", "lidm");
		retv = -1;
		goto exit_10;
	}
	retv = maria_query(db, 1, "select count(*) from barbarian where " \
			"mac = '%s'", inf->mac);
	if (unlikely(retv)) {
		retv = -3;
		elog("select from barbarian failed\n");
		goto exit_20;
	}
	found = 0;
	row = mysql_fetch_row(db->res);
	if (likely(row && row[0]))
		found = atoi(row[0]);
	else
		elog("logic error: no result from count(*) of barbarian\n");
	maria_free_result(db);
	if (unlikely(found)) {
		if (trusted)
			maria_query(db, 0, "delete from barbarian where " \
					"mac = '%s'", inf->mac);
		goto exit_20;
	}
	retv = maria_query(db, 1, "select mac, mac2, last, uuid from citizen " \
		       	"where mac = '%s' or mac2 = '%s'", inf->mac, inf->mac);
	if (unlikely(retv)) {
		retv = -6;
		elog("select mac/mac2 failed\n");
		goto exit_20;
	}
	char *macadr, *macadr2, *last, *uuid;
	macadr = buf;
	macadr2 = buf + 24;
	last = macadr2 + 24;
	uuid = last + 16;
	found = 0;
	row = mysql_fetch_row(db->res);
	if (row) {
		/* mac already in database */
		found = 1;
		if (row[0])
			strcpy(macadr, row[0]);
		else
			macadr = NULL;
		if (row[1])
			strcpy(macadr2, row[1]);
		else
			macadr2 = NULL;
		if (row[2])
			strcpy(last, row[2]);
		else
			last = NULL;
		if (row[3])
			strcpy(uuid, row[3]);
		else
			uuid = NULL;
		assert(last);
	}
	maria_free_result(db);
	if (found) {
		tm = atoll(last);
		if (tm < inf->tm) {
			mac2 = 0;
			if (macadr2 && strcmp(macadr2, inf->mac) == 0)
				mac2 = 1;
			update_citizen(db, inf, mac2, uuid, trusted);
		}
		goto exit_20;
	}
	if (unlikely(inf->leave))
		goto exit_20;

	if (trusted) {
		/* new mac found, trust already exists */
		mop.sem_num = 0;
		mop.sem_op = -1;
		mop.sem_flg = SEM_UNDO;
		do {
			retv = semop(semset, &mop, 1);
			if (unlikely(retv == -1 && errno != EINTR)) {
				elog("Cannot acquire lock before " \
						"reset password: %s\n",
						strerror(errno));
				goto exit_20;
			}
		} while (retv == -1 && errno == EINTR);
		retv = fetch_osinfo(oinf, inf->ip, buf, buflen);
		if (unlikely(retv)) {
			elog("Cannot fetch OS info\n");
			goto exit_100;
		}
		found = 0;
		retv = maria_query(db, 1, "select count(*) from citizen where "\
				"uuid = '%s'", oinf->uuid);
		if (unlikely(retv)) {
			elog("citizen count select failed: %s\n", oinf->uuid);
			goto exit_100;
		}
		row = mysql_fetch_row(db->res);
		if (likely(row))
			found = atoi(row[0]);
		maria_free_result(db);
		if (found) {
			retv = maria_query(db, 0, "update citizen set "\
					"mac2 = '%s', last = %lu, ip2 = '%s' "\
				      	"where  uuid = '%s'", inf->mac, inf->tm,
					inf->ip, oinf->uuid);
			if (unlikely(retv))
				elog("Cannot Set mac2/ip2: %s\n", __func__);
		} else {
			retv = reset_default_passwd(db, inf, cmdbuf, buflen);
			if (unlikely(retv != 0))
				elog("reset_passwd failed\n");
		}
exit_100:
		mop.sem_op = 1;
		semop(semset, &mop, 1);
		goto exit_20;
	}

	/* new mac found, no trust exists */
	unsigned long hseq = 0;
	retv = maria_query(db, 1, "show columns from citizen");
	if (unlikely(retv)) {
		elog("Cannot get column definitions of citizen\n");
		goto exit_20;
	}
	row = mysql_fetch_row(db->res);
	if (unlikely(!row)) {
		elog("Internal logic error, no default password.\n");
		maria_free_result(db);
		retv = -7;
		goto exit_20;
	}
	while (row) {
		if (strcmp(row[0], "admin") == 0)
			strcpy(oinf->user, row[4]);
		else if (strcmp(row[0], "password") == 0)
			strcpy(oinf->passwd, row[4]);
		else if (strcmp(row[0], "hostname") == 0)
			strcpy(oinf->hostname, row[4]);
		row = mysql_fetch_row(db->res);
	}
	maria_free_result(db);
	retv = maria_query(db, 1, "select last_insert_id()");
	if (unlikely(retv != 0)) {
		elog("select last_insert_id() failed\n");
		goto exit_20;
	}
	row = mysql_fetch_row(db->res);
	if (likely(row))
		hseq = atoll(row[0]);
	maria_free_result(db);
	if (unlikely(!row)) {
		elog("no last_insert_id() exists\n");
		goto exit_20;
	}
	len = strlen(oinf->hostname);
	sprintf(oinf->hostname+len, "%04lu", hseq+1);
	random_passwd(oinf->passwd_new);

	mop.sem_num = 0;
	mop.sem_op = -1;
	mop.sem_flg = SEM_UNDO;
	do {
		retv = semop(semset, &mop, 1);
		if (unlikely(retv == -1 && errno != EINTR)) {
			elog("Cannot acquire lock before ssh_copyid: %s\n",
					strerror(errno));
			goto exit_20;
		}
	} while (retv == -1 && errno == EINTR);
	retv = ssh_copyid(buf, buflen, oinf);
	if (unlikely(retv != 0)) {
		if (retv != 10000) {
			elog("ssh_copyid failed\n");
			retv = -8;
		} else {
			if (verbose)
				elog("trust established already\n");
			retv = 0;
		}
		goto exit_30;
	}
	retv = fetch_osinfo(oinf, inf->ip, buf, buflen);
	if (retv) {
		elog("Cannot get OS info of %s\n", inf->ip);
		goto exit_30;
	}

	retv = ssh_probe(buf, buflen, oinf);
	if (verbose && buf[0] != 0)
		elog("%s\n", buf);
	if (unlikely(retv != 0)) {
		elog("ssh_probe %s failed\n", oinf->ip);
		goto exit_30;
	}
	if (verbose)
		elog("new hostname: %s, new password: '%s' for %s\n",
				oinf->hostname, oinf->passwd_new, inf->mac);
	retv = maria_query(db, 0, "insert into citizen (mac, ip, birth, " \
			"last, hostname, password, uuid, serial) values " \
			"('%s', '%s', %lu, %lu, '%s', '%s', '%s', '%s')", \
			inf->mac, inf->ip, inf->tm, inf->tm, oinf->hostname,
			oinf->passwd_new, oinf->uuid, oinf->serial);
	if (retv) {
		elog("Cannot insert new record for %s.\n", inf->mac);
		retv = -7;
	}

exit_30:
	mop.sem_op = 1;
	semop(semset, &mop, 1);

exit_20:
	maria_exit(db);
exit_10:
	free(db);
	return retv;
}
