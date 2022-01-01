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
	char *curp, *saveptr;
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
	curp = strtok_r(resbuf, splits, &saveptr);
	while (curp && count < 2) {
		if (strcmp(curp, "UUID") == 0) {
			curp = strtok_r(NULL, splits, &saveptr);
			strcpy(oinf->uuid, curp+1);
			count += 1;
		} else if (strcmp(curp, "Serial Number") == 0) {
			curp = strtok_r(NULL, splits, &saveptr);
			strcpy(oinf->serial, curp+1);
			count += 1;
		}
		curp = strtok_r(NULL, ":\n", &saveptr);
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

	mesg = malloc(CMDLEN+MSGLEN);
	if (!mesg) {
		elog("Out of Memory\n");
		exit(100);
	}
	retv = ssh_execute(mesg, CMDLEN+MSGLEN, ip, rcmd, NULL, 0);
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

static inline unsigned int poor_hash(unsigned long seed)
{
	unsigned int res;

	res = 0;
	while (seed) {
		res ^= (seed & 0x0ff);
		seed >>= 8;
	}
	return res;
}

static int host_lock(const struct lease_info *inf)
{
	int retv;
	struct sembuf mop;

	mop.sem_num = poor_hash(inf->hostid);
	mop.sem_op = -1;
	mop.sem_flg = SEM_UNDO;
	do {
		retv = semop(inf->semset, &mop, 1);
		if (unlikely(retv == -1 && errno != EINTR))
			break;
	} while (retv == -1 && errno == EINTR);
	return retv;
}

static inline int host_unlock(const struct lease_info *inf)
{
	struct sembuf mop;

	mop.sem_num = poor_hash(inf->hostid);
	mop.sem_op = 1;
	return semop(inf->semset, &mop, 1);
}

static int update_untrust(struct maria *db, const struct lease_info *inf)
{
	int retv;

	retv = host_lock(inf);
	if (unlikely(retv)) {
		elog("Failed to lock host for updating untrusting host\n");
		return retv;
	}
	if (trust_probe(inf->ip) == 0)
		goto exit_10;
	retv = maria_query(db, 0, "delete from citizen where mac" \
			" = '%s' or mac2 = '%s'", inf->mac, inf->mac);
	if (unlikely(retv))
		elog("failed to delete untrusting mac from citizen\n");
	else 
		elog("MAC: %s record deleted\n", inf->mac);
exit_10:
	host_unlock(inf);
	return retv;
}

static int update_trusted(struct maria *db, const struct lease_info *inf,
		int mac2)
{
	int retv = 0;

	if (mac2) {
		retv = maria_query(db, 0, "update citizen set tries = 0, " \
				"last = %lu, ip2 = '%s' where " \
				"mac2 = '%s'", inf->tm, inf->ip, inf->mac);
		if (unlikely(retv))
			elog("Cannot update citizen mac2 %s, ip %s.\n",
					inf->mac, inf->ip);
	} else {
		retv = maria_query(db, 0, "update citizen set tries = 0, " \
				"last = %lu, ip = '%s' where " \
				"mac = '%s'", inf->tm, inf->ip, inf->mac);
		if (unlikely(retv))
			elog("Cannot update citizen mac: %s, ip: %s.\n",
					inf->mac, inf->ip);
	}
	return retv;
}

static int update_citizen(struct maria *db, const struct lease_info *inf,
		int mac2, const char *uuid, int trusted)
{
	int retv = 0;

	if (inf->leave) {
		retv = maria_query(db, 0, "update citizen set last = 0 " \
				"where mac = '%s' or mac2 = '%s'", inf->mac);
		if (unlikely(retv))
			elog("Cannot update citizen for %s, leave\n", inf->mac);
	} else {
		if (!trusted) {
			/* mac already in database, trust not build */
			retv = update_untrust(db, inf);
		} else {
			/* mac already in database, trust exists */
			assert(uuid != NULL);
			retv = update_trusted(db, inf, mac2);
		}
	}
	return retv;
}

#define TRUST_ALREADY	10000

static int ssh_copyid(char *res, int reslen, const struct os_info *oinf)
{
	char *cmdline, *mesg, passwd[16], *input;
	int retv;
	static const char *cpyfmt = "sshpass -p %s ssh-copy-id %s@%s";
	static const char *tstfmt = "ssh -l %s %s sudo -S cp -r .ssh /root/";

	assert(reslen >= CMDLEN+INPLEN+MSGLEN);
	retv = trust_probe(oinf->ip);
	if (unlikely(retv == 0))
		return TRUST_ALREADY;
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

static int insert_trusted(struct os_info *oinf, const struct lease_info *inf,
		struct maria *db, char *buf, int buflen)
{
	int retv, found;
	MYSQL_ROW row;

	retv = fetch_osinfo(oinf, inf->ip, buf, buflen);
	if (unlikely(retv)) {
		elog("Cannot fetch OS info\n");
		return retv;
	}
	found = 0;
	retv = maria_query(db, 1, "select last from citizen where uuid = '%s'",
			oinf->uuid);
	if (unlikely(retv)) {
		elog("citizen uuid select failed: %s\n", oinf->uuid);
		return retv;
	}
	row = mysql_fetch_row(db->res);
	if (likely(row && row[0]))
		found = 1;
	maria_free_result(db);
	if (found) {
		retv = maria_query(db, 0, "update citizen set mac2 = '%s', " \
				"last = %lu, ip2 = '%s' where  uuid = '%s'",
				inf->mac, inf->tm, inf->ip, oinf->uuid);
		if (unlikely(retv))
			elog("Cannot Set mac2/ip2: %s\n", __func__);
		retv = maria_query(db, 0, "delete from citizen " \
				"where mac = '%s'", inf->mac);
		if (unlikely(retv && verbose))
			elog("Delete from citizen where mac = %s failed\n",
					inf->mac);
	} else {
		/* records deleted for the host, reset password */
		retv = reset_default_passwd(db, inf, buf, buflen);
		if (unlikely(retv))
			elog("Unable to reset the password for %s\n", inf->mac);
	}
	return retv;
}

static int insert_untrust(struct os_info *oinf, const struct lease_info *inf,
		struct maria *db, char *buf, int buflen)
{
	int retv, len;
	MYSQL_ROW row;
	char hostseq[8];
	unsigned long hseq = 0;

	retv = maria_query(db, 0, "insert into citizen (mac, ip, birth, last) "\
			"values ('%s', '%s', %ld, %ld)", inf->mac, inf->ip,
			inf->tm, inf->tm);
	if (unlikely(retv)) {
		elog("Insert into citizen failed for %s\n", inf->mac);
		return retv;
	}
	retv = maria_query(db, 1, "select hostname, hostseq, admin, password " \
			"from citizen where mac = '%s'", inf->mac);
	if (unlikely(retv)) {
		elog("Cannot select the newly inserted: %s\n", inf->mac);
		goto err_exit_10;
	}
	row = mysql_fetch_row(db->res);
	if (row) {
		strcpy(oinf->hostname, row[0]);
		strcpy(hostseq, row[1]);
		strcpy(oinf->user, row[2]);
		strcpy(oinf->passwd, row[3]);
	}
	maria_free_result(db);
	if (unlikely(!row)) {
		elog("Logic Error. select returns null for newly inserted: "\
				"%s\n", inf->mac);
		goto err_exit_10;
	}
	hseq = atoll(hostseq);
	len = strlen(oinf->hostname);
	sprintf(oinf->hostname+len, "%04lu", hseq);
	random_passwd(oinf->passwd_new);

	retv = ssh_copyid(buf, buflen, oinf);
	if (unlikely(retv != 0)) {
		if (retv == TRUST_ALREADY) {
			elog("trust built up when doing ssh-copyid\n");
			retv = 0;
		} else
			elog("ssh_copyid failed\n");
		goto err_exit_10;
	}

	retv = fetch_osinfo(oinf, inf->ip, buf, buflen);
	if (retv) {
		elog("Cannot get OS info of %s\n", inf->ip);
		goto err_exit_10;
	}
	retv = ssh_probe(buf, buflen, oinf);
	if (verbose && buf[0] != 0)
		elog("probe: %s\n", buf);
	if (unlikely(retv != 0)) {
		elog("ssh_probe %s failed\n", oinf->ip);
		goto err_exit_10;
	}
	if (verbose)
		elog("new hostname: %s, new password: '%s' for %s\n",
				oinf->hostname, oinf->passwd_new, inf->mac);
	retv = maria_query(db, 0, "update citizen set hostname = '%s', " \
			"password = '%s', uuid = '%s', serial = '%s' where " \
			"mac = '%s'", oinf->hostname, oinf->passwd_new,
			oinf->uuid, oinf->serial, inf->mac);
	if (retv) {
		elog("Cannot insert new record for %s.\n", inf->mac);
		goto err_exit_10;
	}
	return retv;

err_exit_10:
	retv = maria_query(db, 0, "delete from citizen where mac = '%s'",
			inf->mac);
	if (unlikely(retv))
		elog("Cannot delete newly inserted: %s\n", inf->mac);
	return retv;
}

int dbproc(const struct lease_info *inf, const char *usrnam)
{
	struct maria *db;
	int retv = 0, trusted, unreachable;
	int found, mac2, buflen;
	MYSQL_ROW row;
	time_t tm;
	struct os_info *oinf;
	char *buf;

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

	retv = maria_init(db, "lidm", usrnam);
	if (unlikely(retv != 0)) {
		elog("Cannot initialize db connection to %s\n", "lidm");
		retv = -1;
		goto exit_10;
	}
	retv = maria_query(db, 1, "select mac from barbarian where " \
			"mac = '%s'", inf->mac);
	if (unlikely(retv)) {
		retv = -3;
		elog("select from barbarian failed\n");
		goto exit_20;
	}
	found = 0;
	row = mysql_fetch_row(db->res);
	if (unlikely(row && row[0]))
		found = 1;
	maria_free_result(db);
	if (unlikely(found)) {
	       	if (verbose)
			elog("Mac: %s in barbarian\n", inf->mac);
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
	unreachable = 0;
	trusted = 0;
	if (!inf->leave) {
		retv = trust_probe(inf->ip);
		if (retv == 1024) {
			unreachable = 1;
			elog("client %s unreachable\n", inf->ip);
		}
		trusted = retv == 0;
	}
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
	if (unlikely(inf->leave || unreachable))
		goto exit_20;

	/* a mac address come up */
	retv = host_lock(inf);
	if (unlikely(retv))
		goto exit_20;
	if (trusted) {
		/* new mac found, trust already exists */
		retv = insert_trusted(oinf, inf, db, buf, buflen);
	} else {
		/* new mac found, no trust exists */
		retv = insert_untrust(oinf, inf, db, buf, buflen);
	}
	host_unlock(inf);

exit_20:
	maria_exit(db);
exit_10:
	free(db);
	return retv;
}
