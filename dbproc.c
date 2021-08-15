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
#include "miscs.h"
#include "pipe_execution.h"
#include "dbproc.h"
#include "dbconnect.h"
#include "random_passwd.h"

static inline void fill_osinfo(char *buf, struct os_info *oinf)
{
	char *curp;
	int count = 0;

	curp = strtok(buf, ":\n");
	while (curp && count < 2) {
		if (strcmp(curp, "UUID") == 0) {
			curp = strtok(NULL, ":\n");
			strcpy(oinf->uuid, curp+1);
			count += 1;
		} else if (strcmp(curp, "Serial Number") == 0) {
			curp = strtok(NULL, ":\n");
			strcpy(oinf->serial, curp+1);
			count += 1;
		}
		curp = strtok(NULL, ":\n");
	}
}

static inline void ssh_remove_stale_ip(const char *ip)
{
	char *cmd, *res, *known_hosts;
	struct passwd *pwd;
	static const char *fmt = "ssh-keygen -R %s";
	static const char *hosts_old = "/.ssh/known_hosts.old";

	pwd = getpwuid(getuid());
	assert(pwd);

	cmd = malloc(2048);
	res = cmd + 1024;
	known_hosts = cmd;
	strcpy(known_hosts, pwd->pw_dir);
	strcat(known_hosts, hosts_old);
	unlink(known_hosts);

	sprintf(cmd, fmt, ip);
	pipe_execute(res, 1024, cmd, NULL);
	free(cmd);
}

static int ssh_probe(char *res, int reslen, const struct os_info *oinf)
{
	int retv;
	char *cmdbuf;
	char *passwd, *input;
	static const char *fmt = "sshpass -p %s ssh -l %s %s sudo -S " \
			  "lios_lock_probe.py --hostname %s --password %s " \
			  "--username %s";

	ssh_remove_stale_ip(oinf->ip);
	*res = 0;
	cmdbuf = malloc(1024+64);
	sprintf(cmdbuf, fmt, oinf->passwd, oinf->user, oinf->ip,
			oinf->hostname, oinf->passwd_new, oinf->user);
	passwd = cmdbuf + 1024;
	input = passwd + 16;
	strcpy(passwd, oinf->passwd);
	strcat(passwd, "\n");
	strcpy(input, passwd);
	strcat(input, passwd);
	strcat(input, passwd);
	retv = pipe_execute(res, reslen, cmdbuf, input);
	free(cmdbuf);
	return retv;
}

static const char *host_id_changed = "WARNING: REMOTE HOST IDENTIFICATION HAS" \
				     " CHANGED!";

static int update_citizen(struct maria *db, const struct lease_info *inf,
		int mac2, const char *uuid)
{
	int retv = 0, nfields, updated, tries;
	char *mesg, *cmdbuf, hostname[16];
	struct os_info oinf;
	MYSQL_ROW row;
	unsigned long tm;

	retv = 0;
	updated = 0;
	tm = inf->tm;
	if (inf->leave)
		tm = 0;
	if (mac2) {
		retv = maria_query(db, 0, "update citizen set last = %lu, " \
				"ip2 = '%s' where mac2 = '%s'",
				(unsigned long)tm, inf->ip, inf->mac);
		updated = 1;
	} else if (uuid && strlen(uuid) > 10) {
		retv = maria_query(db, 0, "update citizen set last = %lu, " \
				"ip = '%s' where mac = '%s'",
				(unsigned long)tm, inf->ip, inf->mac);
		updated = 1;
	}
	if (updated || inf->leave) {
		if (retv)
			elog("Cannot update citizen: %s, ip: %s.\n", inf->mac,
					inf->ip);
		return retv;
	}

	retv = maria_query(db, 1, "select tries from citizen where mac = '%s'",
			inf->mac);
	if (unlikely(retv != 0)) {
		elog("DB query error for 'tries': %s\n", inf->mac);
		return retv;
	}
	row = mysql_fetch_row(db->res);
	if (!row) {
		elog("Internal logic error. search 'tries' failed for %s\n",
				inf->mac);
		return retv;
	}
	tries = atoi(row[0]);
	maria_free_result(db);
	tries += 1;
	if (tries > 5) {
		retv = maria_query(db, 0, "start transaction");
		if (unlikely(retv))
			return retv;
		retv = maria_query(db, 0, "insert into barbarian (mac) values" \
				"('%s')", inf->mac);
		if (unlikely(retv))
			return retv;
		retv = maria_query(db, 0, "delete from citizen where mac = " \
				"'%s'", inf->mac);
		if (unlikely(retv))
			return retv;
		retv = maria_query(db, 0, "commit release");
		return retv;
	}

	mesg = malloc(1024);
	memset(&oinf, 0, sizeof(oinf));
	cmdbuf = mesg;
	sprintf(cmdbuf, "ssh -o BatchMode=yes -l root %s ls", inf->ip);
	retv = pipe_execute(mesg, 1024, cmdbuf, NULL);
	if (strstr(mesg, host_id_changed))
		ssh_remove_stale_ip(inf->ip);
	if (retv != 0) {
		retv = maria_query(db, 0, "update citizen set tries = %d where " \
				"mac = '%s'", tries, inf->mac);
		if (retv)
			elog("Cannot set failed tries for '%s'\n", inf->mac);
		goto exit_10;
	}

	retv = ssh_execute(mesg, 1024, inf->ip, "smird", 0);
	if (retv != 0) {
		elog("Cannot get the UUID of %s\n", inf->ip);
		goto exit_10;
	}
	fill_osinfo(mesg, &oinf);
	retv = maria_query(db, 1, "select last from citizen where uuid = " \
			"'%s'", oinf.uuid);
	if (unlikely(retv != 0)) {
		elog("Cannot query for uuid: %s.\n", oinf.uuid);
		goto exit_10;
	}
	nfields = mysql_num_fields(db->res);
        assert(nfields == 1);
	row = mysql_fetch_row(db->res);
	if (!row) {
		elog("still no such uuid: %s. Try add it to DB\n", oinf.uuid);
		maria_free_result(db);
		retv = maria_query(db, 1, "select hostname, hostseq from " \
				"citizen where mac = '%s'", inf->mac);
		if (unlikely(retv != 0)) {
			elog("Cannot select hostname from citizen where mac "\
					"= %s\n", inf->mac);
			goto exit_10;
		}
		row = mysql_fetch_row(db->res);
		if (unlikely(!row))  {
			elog("No hosts with mac = %s\n", inf->mac);
			goto exit_10;
		}
		sprintf(hostname, "%s%04lld", row[0], atoll(row[1])%100000);
		maria_free_result(db);
		retv = maria_query(db, 0, "update citizen set uuid = '%s', " \
				"password = '*', hostname = '%s', " \
				"serial = '%s' where mac = '%s'",
				oinf.uuid, hostname, oinf.serial, inf->mac);
		if (unlikely(retv != 0))
			elog("Cannot add uuid %s into DB.\n");
		goto exit_10;
	}
	tm = atoll(row[0]);
	maria_free_result(db);
	if (tm < inf->tm)
		tm = inf->tm;
	retv = maria_query(db, 0, "update citizen set mac2 = '%s', " \
			"ip2 = '%s', last = %lu where uuid = '%s'", 
			inf->mac, inf->ip, tm, oinf.uuid);
	if (retv) {
		elog("Cannot update citizen where uuid = %s\n", oinf.uuid);
		goto exit_10;
	}
	retv = maria_query(db, 0, "delete from citizen where mac = " \
			"'%s'", inf->mac);
	if (retv)
		elog("Cannot delete mac = %s from citizen.\n", inf->mac);

exit_10:
	free(mesg);
	return retv;
}

static int ssh_copyid(char *res, int reslen, const struct os_info *oinf)
{
	char *cmdline, *passwd, *input;
	int retv;
	static const char *cpyfmt = "sshpass -p %s ssh-copy-id %s@%s";
	static const char *tstfmt = "ssh -l %s %s sudo -S cp -r .ssh /root/";

	cmdline = malloc(1024);
	passwd = cmdline + 512;
	input = passwd + 128;
	sprintf(cmdline, cpyfmt, oinf->passwd_new, oinf->user, oinf->ip);
	retv = pipe_execute(res, reslen, cmdline, NULL);
	if (retv != 0)
		goto exit_10;
	sprintf(cmdline, tstfmt, oinf->user, oinf->ip);
	strcpy(passwd, oinf->passwd_new);
	strcat(passwd, "\n");
	strcpy(input, passwd);
	strcat(input, passwd);
	strcat(input, passwd);
	retv = pipe_execute(res, reslen, cmdline, input);

exit_10:
	free(cmdline);
	return retv;
}

int dbproc(const struct lease_info *inf)
{
	struct maria *db;
	int retv = 0;
	int nfields, found, mac2;
	MYSQL_ROW row;
	time_t tm;
	const char *uuid;
	struct os_info *oinf;
	char *buf;

	db = malloc(sizeof(struct maria)+sizeof(struct os_info)+1024);
	if (unlikely(!db)) {
		elog("Out of Memory.\n");
		retv = -1;
		return retv;
	}
	oinf = (struct os_info *)(db + 1);
	oinf->ip = inf->ip;
	buf = (char *)(oinf + 1);

	retv = maria_init(db, "lidm");
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
	if (row && row[0])
		found = atoi(row[0]);
	else
		elog("Internal logic error: no result from count(*)\n");
	maria_free_result(db);
	if (found)
		goto exit_20;

	retv = maria_query(db, 1, "select mac, mac2, last, uuid from citizen " \
		       	"where mac = '%s' or mac2 = '%s'", inf->mac, inf->mac);
	if (unlikely(retv)) {
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
	if (inf->leave)
		goto exit_20;
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

	random_passwd(oinf->passwd_new);
	retv = ssh_probe(buf, 1024, oinf);
	printf("%s\n", buf);
	if (retv != 0) {
		elog("ssh_probe %s failed\n", oinf->ip);
		retv = -6;
		goto exit_20;
	}
	printf("%s new hostname: %s, new password: '%s'\n", inf->mac,
			oinf->hostname, oinf->passwd_new);
	retv = maria_query(db, 0, "start transaction");
	if (unlikely(retv != 0)) {
		elog("Cannot start a db transaction.\n");
		retv = -retv;
		goto exit_20;
	}
	retv = maria_query(db, 0, "update citizen set hostname = '%s', " \
			"password= '%s' where mac = '%s'", oinf->hostname,
			oinf->passwd_new, inf->mac);
	if (retv) {
		elog("Cannot update hostname and password.\n");
		retv = -7;
		goto exit_20;
	}
	retv = ssh_copyid(buf, 1024, oinf);
	if (retv != 0) {
		elog("ssh_copyid failed\n");
		retv = -8;
		goto exit_20;
	}
	retv = ssh_execute(buf, 1024, inf->ip, "smird", 0);
	printf("%s\n", buf);
	if (retv != 0) {
		retv = -8;
		goto exit_20;
	}
	fill_osinfo(buf, oinf);
	retv = maria_query(db, 0, "update citizen set uuid = '%s', serial = " \
			"'%s' where mac = '%s'", oinf->uuid, oinf->serial,
			inf->mac);
	if (retv != 0) {
		retv = -9;
		goto exit_20;
	}
	retv = maria_query(db, 0, "commit release");

exit_20:
	maria_exit(db);
exit_10:
	free(db);
	return retv;
}
