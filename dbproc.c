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
static const int MSGLEN = 1536;

static int fetch_osinfo(struct os_info *oinf, const char *ip,
		char *resbuf, int len)
{
	int retv, count;
	char *curp;
	static const char *splits = ":\n";

	retv = ssh_execute(resbuf, len, ip, "smird", NULL, 0);
	if (verbose)
		elog("%s\n", resbuf);
	if (unlikely(retv != 0)) {
		elog("Cannot fetch os info using \"smird\"\n");
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
	int retv, len;
	char *cmdbuf, *msgbuf;
	char passwd[16], input[48];
	static const char *fmt = "ssh -l root %s lios_lock_probe.py " \
				  "--hostname %s --password %s --username %s";

	assert(reslen >= CMDLEN+MSGLEN);
	*res = 0;
	cmdbuf = res;
	msgbuf = cmdbuf + CMDLEN;
	len = sprintf(cmdbuf, fmt, oinf->ip, oinf->hostname,
			oinf->passwd_new, oinf->user);
	assert(len < CMDLEN);
	strcpy(passwd, oinf->passwd);
	strcat(passwd, "\n");
	strcpy(input, passwd);
	strcat(input, passwd);
	strcat(input, passwd);
	retv = pipe_execute(msgbuf, MSGLEN, cmdbuf, input);
	return retv;
}

static const char *host_id_changed = "WARNING: REMOTE HOST IDENTIFICATION HAS" \
				     " CHANGED!";

static int trust_probe(const char *ip)
{
	char *cmdbuf, *mesg;
	int retv;

	cmdbuf = malloc(CMDLEN+MSGLEN);
	if (!cmdbuf) {
		elog("Out of Memory\n");
		exit(100);
	}
	mesg = cmdbuf + CMDLEN;
	sprintf(cmdbuf, "ssh -o BatchMode=Yes -l root %s pwd", ip);
	retv = pipe_execute(mesg, MSGLEN, cmdbuf, NULL);
	if (strstr(mesg, host_id_changed)) {
		ssh_remove_stale_ip(ip);
		retv = pipe_execute(mesg, MSGLEN, cmdbuf, NULL);
	}
	free(cmdbuf);
	return retv;
}

static int update_citizen(struct maria *db, const struct lease_info *inf,
		int mac2, const char *uuid, int trusted)
{
	int retv = 0, tries;
	char *mesg = NULL;
	struct os_info oinf;
	MYSQL_ROW row;
	unsigned long tm;

	if (!trusted && !inf->leave) {
		if (uuid) {
			retv = maria_query(db, 0, "delete from citizen " \
					"where mac = '%s' or mac2 = '%s'", \
					inf->mac, inf->mac);
			return retv;
		}
		retv = maria_query(db, 1, "select tries from citizen " \
				"where mac = '%s'", inf->mac);
		if (unlikely(retv != 0)) {
			elog("DB query error for 'tries': %s\n", inf->mac);
			return retv;
		}
		row = mysql_fetch_row(db->res);
		if (unlikely(!row)) {
			elog("Internal logic error. search 'tries' failed for %s\n",
					inf->mac);
			maria_free_result(db);
			return retv;
		}
		tries = atoi(row[0]);
		maria_free_result(db);
		tries += 1;
		if (tries > 5) {
			elog("Maximu tries to manange %s failed. " \
					"Move to barbarian\n", inf->mac);
			retv = maria_transact(db);
			if (unlikely(retv))
				return retv;
			retv = maria_query(db, 0, "insert into barbarian " \
					"(mac) values ('%s')", inf->mac);
			if (unlikely(retv))
				return retv;
			retv = maria_query(db, 0, "delete from citizen " \
					"where mac = '%s'", inf->mac);
			if (unlikely(retv))
				return retv;
			retv = maria_commit(db);
			if (unlikely(retv))
				elog("Commit failed. Insertion into barbarian:"\
					       	"%s\n", maria_error(db));
		} else {
			retv = maria_query(db, 0, "update citizen set tries " \
					"= %d where mac = '%s'", tries, inf->mac);
			if (retv)
				elog("Cannot set failed tries for '%s'\n",
						inf->mac);
		}
		if (verbose)
			elog("%d time to manange %s failed.\n",
					tries, inf->mac);
		return retv;
	}

	mesg = malloc(CMDLEN+MSGLEN);
	if (!mesg) {
		elog("Out of Memory\n");
		return -ENOMEM;
	}
	memset(&oinf, 0, sizeof(oinf));
	retv = 0;
	tm = inf->tm;
	if (inf->leave)
		tm = 0;
	if (mac2) {
		assert(uuid != NULL);
		retv = maria_transact(db);
		if (unlikely(retv != 0)) {
			elog("Cannot start transaction for update mac2\n");
			goto exit_10;
		}
		retv = maria_query(db, 0, "update citizen set last = %lu, " \
				"ip2 = '%s' where mac2 = '%s'",
				(unsigned long)tm, inf->ip, inf->mac);
		if (unlikely(retv))
			elog("Cannot update citizen: %s, ip: %s.\n",
					inf->mac, inf->ip);
		retv = maria_commit(db);
		if (unlikely(retv != 0 && verbose))
			elog("Commit update mac2 fail: %s\n", maria_error(db));
	} else if (uuid) {
		retv = maria_transact(db);
		if (unlikely(retv != 0)) {
			elog("Cannot start transaction for update mac\n");
			goto exit_10;
		}
		retv = maria_query(db, 0, "update citizen set last = %lu, " \
			"ip = '%s' where mac = '%s'",
			(unsigned long)tm, inf->ip, inf->mac);
		if (unlikely(retv))
			elog("Cannot update citizen: %s, ip: %s.\n",
					inf->mac, inf->ip);
		retv = maria_commit(db);
		if (unlikely(retv != 0 && verbose))
			elog("Cannot commit update mac: %s\n", maria_error(db));
	} else {
		retv = fetch_osinfo(&oinf, inf->ip, mesg, CMDLEN+MSGLEN);
		if (unlikely(retv != 0)) {
			elog("Cannot fetch OS info\n");
			goto exit_10;
		}
		retv = maria_query(db, 1, "select count(*) from citizen " \
				"where uuid = '%s'", oinf.uuid);
		if (unlikely(retv != 0)) {
			elog("Cannot query for uuid: %s.\n", oinf.uuid);
			goto exit_10;
		}
		row = mysql_fetch_row(db->res);
		if (unlikely(!row || atoi(row[0]) == 0)) {
			elog("Still no such uuid: %s. Wait for next echo\n",
					oinf.uuid);
			maria_free_result(db);
			goto exit_10;
		}
		maria_free_result(db);
		retv = maria_transact(db);
		if (unlikely(retv)) {
			elog("Cannot start a transaction\n");
			goto exit_10;
		}
		retv = maria_query(db, 0, "update citizen set mac2 = '%s', " \
				"ip2 = '%s', last = %lu where uuid = '%s'", 
				inf->mac, inf->ip, tm, oinf.uuid);
		if (unlikely(retv)) {
			elog("Cannot update citizen where uuid = %s\n",
					oinf.uuid);
			goto exit_10;
		}
		retv = maria_query(db, 0, "delete from citizen where mac = " \
				"'%s'", inf->mac);
		if (unlikely(retv)) {
			elog("Cannot delete mac = %s from citizen.\n", inf->mac);
			goto exit_10;
		}
		retv = maria_commit(db);
		if (unlikely(retv && verbose))
			elog("Cannot commit update mac2 and ip2: %s\n",
					maria_error(db));
	}

exit_10:
	free(mesg);
	return retv;
}

static int ssh_copyid(char *res, int reslen, const struct os_info *oinf)
{
	char *cmdline, *mesg, passwd[16], input[48];
	int retv;
	static const char *cpyfmt = "sshpass -p %s ssh-copy-id %s@%s";
	static const char *tstfmt = "ssh -l %s %s sudo -S cp -r .ssh /root/";

	assert(reslen >= CMDLEN+MSGLEN);
	retv = trust_probe(oinf->ip);
	if (unlikely(retv == 0))
		return 10000;

	cmdline = res;
	mesg = cmdline + CMDLEN;
	sprintf(cmdline, cpyfmt, oinf->passwd, oinf->user, oinf->ip);
	retv = pipe_execute(mesg, MSGLEN, cmdline, NULL);
	if (unlikely(retv != 0)) {
		elog("ssh-copy-id failed: %s\n", mesg);
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
		elog("ssh-copy-id failed in copying to root: %s\n", mesg);
	return retv;
}

int dbproc(const struct lease_info *inf, int semset, const char *usrnam)
{
	struct maria *db;
	int retv = 0, trusted;
	int found, mac2;
	MYSQL_ROW row;
	time_t tm;
	const char *uuid;
	struct os_info *oinf;
	char *buf;
	struct sembuf mop;

	trusted = 0;
	if (!inf->leave)
		trusted = trust_probe(inf->ip) == 0;
	db = malloc(sizeof(struct maria)+sizeof(struct os_info)+CMDLEN+MSGLEN);
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
	retv = maria_query(db, 1, "select count(*) from barbarian where " \
			"mac = '%s'", inf->mac);
	if (unlikely(retv)) {
		retv = -3;
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
		goto exit_20;
	}
	row = mysql_fetch_row(db->res);
	if (row) {
		tm = atoll(row[2]);
		uuid = row[3];
		if (tm < inf->tm) {
			mac2 = 0;
			if (row[1] && strcmp(row[1], inf->mac) == 0)
				mac2 = 1;
			update_citizen(db, inf, mac2, uuid, trusted);
		}
		row = mysql_fetch_row(db->res);
		if (row)
			elog("Internal logic error: dublicate citizen records.\n");
		goto exit_30;
	}
	if (unlikely(inf->leave))
		goto exit_30;

	if (trusted) {
		retv = fetch_osinfo(oinf, inf->ip, buf, CMDLEN+MSGLEN);
		if (unlikely(retv))
			goto exit_20;
		retv = maria_query(db, 1, "select count(*) from citizen where "\
				"uuid = '%s'", oinf->uuid);
		if (unlikely(retv))
			goto exit_30;
		row = mysql_fetch_row(db->res);
		if (likely(row && atoi(row[0]) > 0)) {
			retv = maria_query(db, 0, "update citizen set "\
					"mac2 = '%s', last = %lu, ip2 = '%s' "\
				      	"where  uuid = '%s'", inf->mac, inf->tm,
					inf->ip, oinf->uuid);
			if (unlikely(retv))
				elog("update to mac2 failed\n");
		} else {
			elog("Fatal error: MAC = %s, IP = %s, trusted but no "\
					"uuid: %s in citizen\n", inf->mac,
					inf->ip, oinf->uuid);
		}
		goto exit_30;
	}

	retv = maria_transact(db);
	if (unlikely(retv != 0)) {
		elog("Cannot start a db transaction.\n");
		retv = -retv;
		goto exit_20;
	}
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
	row = mysql_fetch_row(db->res);
	if (!row) {
		elog("Internal logic error, no default password.\n");
		retv = -7;
		goto exit_30;
	}
	sprintf(oinf->hostname, "%s%04d", row[0], atoi(row[2]));
	strcpy(oinf->passwd, row[1]);
	strcpy(oinf->user, row[3]);
	random_passwd(oinf->passwd_new);
	maria_free_result(db);

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
	retv = ssh_copyid(buf, CMDLEN+MSGLEN, oinf);
	mop.sem_op = 1;
	semop(semset, &mop, 1);
	if (unlikely(retv != 0)) {
		if (retv != 10000) {
			elog("ssh_copyid failed\n");
			retv = -8;
		} else
			retv = 0;
		goto exit_20;
	}
	retv = ssh_probe(buf, CMDLEN+MSGLEN, oinf);
	if (verbose)
		elog("%s\n", buf);
	if (unlikely(retv != 0)) {
		elog("ssh_probe %s failed\n", oinf->ip);
		retv = -6;
		goto exit_20;
	}
	if (verbose)
		elog("%s new hostname: %s, new password: '%s'\n", inf->mac,
			oinf->hostname, oinf->passwd_new);
	retv = maria_query(db, 0, "update citizen set hostname = '%s', " \
			"password= '%s' where mac = '%s'", oinf->hostname,
			oinf->passwd_new, inf->mac);
	if (retv) {
		elog("Cannot update hostname and password.\n");
		retv = -7;
		goto exit_20;
	}
	retv = fetch_osinfo(oinf, inf->ip, buf, CMDLEN+MSGLEN);
	if (retv) {
		elog("Cannot get OS info of %s\n", inf->ip);
		goto exit_20;
	}
	retv = maria_query(db, 0, "update citizen set uuid = '%s', serial = " \
			"'%s' where mac = '%s'", oinf->uuid, oinf->serial,
			inf->mac);
	if (retv != 0) {
		retv = -9;
		goto exit_20;
	}
	retv = maria_commit(db);
	if (unlikely(retv))
		elog("Insert new discovery failed: %s\n", maria_error(db));

exit_30:
	maria_free_result(db);
exit_20:
	maria_exit(db);
exit_10:
	free(db);
	return retv;
}
