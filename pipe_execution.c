#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include "miscs.h"
#include "pipe_execution.h"

#define CMDLEN 512
#define MSGLEN 2048

int pipe_execute(char *res, int reslen, const char *cmdline, const char *input)
{
	int sysret, retv, pfdin[2], pfdout[2], idx;
	int fdout, fdin, numargs, cmdlen, inlen;
	char *curchr, **args, *cmdbuf, *cmd, *lsl, *saveptr;
	const char *ln, *lnmark;
	pid_t subpid;
	int numb, len;

	retv = -1;
	if (!cmdline)
		return retv;
	len = strlen(cmdline);
	if (len < 1)
		return retv;
	cmdlen = (len / sizeof(char *) + 1) * sizeof(char *);
	numargs = 21;
	cmdbuf = malloc(cmdlen+sizeof(char *)*numargs + 128);
	if (!cmdbuf) {
		elog("Out of Memory.\n");
		return -100;
	}
	args = (char **)(cmdbuf + cmdlen);
	cmd = (char *)(args + numargs);
	strcpy(cmdbuf, cmdline);
	retv = pipe(pfdin);
	if (retv == -1) {
		elog("pipe failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_10;
	}
	sysret = pipe(pfdout);
	if (sysret == -1) {
		elog("pipe out failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_20;
	}
	curchr = strtok_r(cmdbuf, " ", &saveptr);
	strcpy(cmd, curchr);
	lsl = strrchr(cmd, '/');
	idx = 0;
	while (curchr && idx < numargs - 1) {
		args[idx++] = curchr;
		curchr = strtok_r(NULL, " ", &saveptr);
	}
	args[idx] = NULL;
	if (lsl)
		args[0] = lsl + 1;
	subpid = fork();
	if (unlikely(subpid == -1)) {
		elog("fork failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_30;
	}
	if (subpid == 0) {
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
#ifdef DEBUG_DSCAO
		FILE *log;
		char *arg;
		int len = 0, cmdlen;
		log = fopen("/tmp/exec.log", "ab");
		fprintf(log, "cmd: %s - %s\n", cmd, cmdline);
		idx = 0;
		arg = args[0];
		len = 0;
		while (arg) {
			len += strlen(arg) + 1;
			fprintf(log, "#%s", arg);
			arg = args[++idx];
		}
		cmdlen = strlen(cmdline);
		fprintf(log, "len compare %d-%d\n", len, cmdlen);
		fclose(log);
		assert(len <= cmdlen + 1);
#endif /* DEBUG_DSCAO */
		if (lsl)
			sysret = execv(cmd, args);
		else
			sysret = execvp(cmd, args);
		if (sysret == -1)
			elog("execv failed: %s\n", strerror(errno));
		exit(1);
	}
	fdout = pfdout[1];
	close(pfdout[0]);
	fdin = pfdin[0];
	close(pfdin[1]);

	struct pollfd pfd;
	pfd.fd = fdout;
	pfd.events = POLLOUT;
	ln = input;
	while (ln && *ln) {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, -1);
		if (pfd.revents & POLLERR)
			break;
		lnmark = strchr(ln, '\n');
		if (lnmark)
			inlen = lnmark - ln + 1;
		else
			inlen = strlen(ln);
		numb = write(fdout, ln, inlen);
		if (numb == -1)
			elog("Write input through pipe failed: %s\n",
					strerror(errno));
		ln += inlen;
	}

	int lenrem, curpos;

	pfd.fd = fdin;
	pfd.events = POLLIN;
	lenrem = reslen - 1;
	curpos = 0;
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, 200);
		if (sysret == 1) {
			if (lenrem == 0) {
				elog("Warning: command %s results overflow.\n",
						cmdline);
				lenrem = reslen - 1;
				curpos = 0;
			}
			if ((pfd.revents & POLLIN) != 0) {
				numb = read(fdin, res+curpos, lenrem);
				if (numb > 0) {
					curpos += numb;
					lenrem -= numb;
				}
			}
		}
		sysret = waitpid(subpid, &retv, WNOHANG);
	} while (sysret == 0);
	pfd.revents = 0;
	sysret = poll(&pfd, 1, 0);
	if (sysret > 0 && (pfd.revents & POLLIN) != 0) {
		if (lenrem == 0) {
			elog("Warning: command %s results overflow.\n",
					cmdline);
			lenrem = reslen - 1;
			curpos = 0;
		}
		if ((pfd.revents & POLLIN) != 0) {
			numb = read(fdin, res+curpos, lenrem);
			if (numb > 0) {
				curpos += numb;
				lenrem -= numb;
			}
		}
	}
	*(res+curpos) = 0;
	if (unlikely(retv != 0))
		elog("failed command: code %X %s\n--->%s\n", retv, cmdline, res);

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

int ssh_execute(char *res, int reslen, const char *ip, const char *cmdline,
		const char *input, int rm)
{
	struct stat mst;
	char *cmdbuf, *cmdfile, *cmd, *tmpres;
	char *lsl, *bsl;
	int sysret, retv = -1, len;
	static const char *cpfmt = "scp -o BatchMode=yes %s root@%s:";
	static const char *exfmt = "ssh -o BatchMode=yes -l root %s ./%s";
	static const char *e0fmt = "ssh -o BatchMode=yes -l root %s %s";
	static const char *rmfmt = "ssh -o BatchMode=yes -l root %s rm ./%s";

	res[0] = 0;
	if (!cmdline)
		return retv;
	cmdbuf = malloc(CMDLEN+MSGLEN+128);
	if (!cmdbuf) {
		elog("Out of Memory\n");
		return 100;
	}
	tmpres = cmdbuf + CMDLEN;
	cmdfile = tmpres + MSGLEN;

	bsl = strchr(cmdline, ' ');
	if (bsl)
		len = bsl - cmdline;
	else
		len = strlen(cmdline);
	strncpy(cmdfile, cmdline, len);
	cmdfile[len] = 0;
	cmd = cmdfile;
	lsl = strrchr(cmdfile, '/');
	if (lsl) {
		cmd = lsl + 1;
		sysret = stat(cmdfile, &mst);
		if (sysret == -1) {
			elog("No such file %s: %s\n", cmdfile,
					strerror(errno));
			retv = -errno;
			goto exit_10;
		}
		sprintf(cmdbuf, cpfmt, cmdfile, ip);
		retv = pipe_execute(tmpres, MSGLEN, cmdbuf, NULL);
		if (unlikely(retv != 0)) {
			elog("ssh copy failed: %s\n", cmdfile);
			goto exit_10;
		}
		len = sprintf(cmdbuf, exfmt, ip, cmd);
	} else
		len = sprintf(cmdbuf, e0fmt, ip, cmd);
	if (bsl)
		sprintf(cmdbuf+len, "%s", bsl);
	retv = pipe_execute(res, reslen, cmdbuf, input);
	if (unlikely(retv != 0))
		goto exit_10;
	if (!rm || !lsl)
		goto exit_10;

	sprintf(cmdbuf, rmfmt, ip, cmd);
	retv = pipe_execute(tmpres, MSGLEN, cmdbuf, NULL);
	if (unlikely(retv != 0))
		elog("Cannot remove file %s at %s-->\n", cmd, ip, tmpres);

exit_10:
	free(cmdbuf);
	return retv;
}
