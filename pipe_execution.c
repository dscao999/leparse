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
#define MAXARGS 21

static int wait_and_get(int subpid, char *res, int reslen, struct pollfd *pfd,
		const char *cmdline)
{
	int lenrem, curpos, retv, sysret, numb;

	lenrem = reslen - 1;
	curpos = 0;
	do {
		pfd->revents = 0;
		sysret = poll(pfd, 1, 200);
		numb = 0;
		if (sysret == 1) {
			if (lenrem == 0) {
				elog("Warning: command %s results overflow.\n",
						cmdline);
				lenrem = reslen - 1;
				curpos = 0;
			}
			if ((pfd->revents & POLLIN) != 0) {
				numb = read(pfd->fd, res+curpos, lenrem);
				if (numb > 0) {
					curpos += numb;
					lenrem -= numb;
				}
			}
		}
		sysret = waitpid(subpid, &retv, WNOHANG);
	} while (sysret == 0 && numb >= 0);
	if (numb == -1 && sysret == 0) {
		elog("PIPE read failed: %s\n", strerror(errno));
		kill(subpid, SIGTERM);
		sysret = waitpid(subpid, &retv, 0);
	}
	pfd->revents = 0;
	sysret = poll(pfd, 1, 0);
	if (sysret > 0 && (pfd->revents & POLLIN) != 0) {
		if (lenrem == 0) {
			elog("Warning: command %s results overflow.\n",
					cmdline);
			lenrem = reslen - 1;
			curpos = 0;
		}
		if ((pfd->revents & POLLIN) != 0) {
			numb = read(pfd->fd, res+curpos, lenrem);
			if (numb > 0) {
				curpos += numb;
				lenrem -= numb;
			}
		}
	}
	*(res+curpos) = 0;
	return retv;
}

static void parse_execute(const char *cmdline)
{
	char *curchr, **args, *cmdbuf, *cmd, *lsl, *saveptr;
	int idx, len, retv = 0, cmdlen, numargs, sysret;

	if (!cmdline)
		exit(retv);
	len = strlen(cmdline);
	if (len < 1)
		exit(retv);
	cmdlen = (len / sizeof(char *) + 1) * sizeof(char *);
	numargs = MAXARGS;
	cmdbuf = malloc(cmdlen+sizeof(char *)*numargs + 128);
	if (!cmdbuf) {
		elog("Out of Memory.\n");
		exit(100);
	}
	args = (char **)(cmdbuf + cmdlen);
	cmd = (char *)(args + numargs);
	strcpy(cmdbuf, cmdline);
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
	if (lsl)
		sysret = execv(cmd, args);
	else
		sysret = execvp(cmd, args);
	if (sysret == -1)
		elog("execv failed: %s\n", strerror(errno));
	exit(errno);
}

int one_execute(char *res, int reslen, const char *cmdline, const char *input)
{
	int sysret, retv, pfdin[2], pfdout[2];
	int fdout, fdin, inlen;
	const char *ln, *lnmark;
	pid_t subpid;
	int numb;

	if (res)
		res[0] = 0;
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
		stdin = fdopen(dup(fdin), "r");
		close(fdin);
		if (res != NULL) {
			fclose(stdout);
			stdout = fdopen(dup(fdout), "w");
			fclose(stderr);
			stderr = fdopen(dup(fdout), "w");
		}
		close(fdout);
		parse_execute(cmdline);
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

	pfd.fd = fdin;
	pfd.events = POLLIN;
	if (res)
		retv = wait_and_get(subpid, res, reslen, &pfd, cmdline);
	else {
		do
			sysret = waitpid(subpid, &retv, 0);
		while (sysret == -1 && errno == EINTR);
		assert(sysret > 0);
	}
	if (unlikely(retv != 0))
		elog("failed command: code %X %s\n--->%s\n", retv, cmdline, res);

exit_30:
	close(pfdout[0]);
	close(pfdout[1]);

exit_20:
	close(pfdin[0]);
	close(pfdin[1]);

exit_10:
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
	static const char *exfmt = "ssh -o BatchMode=yes -l root %s -- ./%s";
	static const char *e0fmt = "ssh -o BatchMode=yes -l root %s -- %s";
	static const char *rmfmt = "ssh -o BatchMode=yes -l root %s rm ./%s";

	if (res)
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

#define MAX_PIPES	10
struct pipe_element {
	const char *cmd;
	pid_t pid;
	int pin, pout;
};

int pipe_execute(char *res, int reslen, const char *cmdline, const char *input)
{
	int sysret, retv, pout, pin, inlen, idx;
	const char *ln;
	int npipes, buflen, pipe_fd[2], len;
	char *cmdbuf, *saveptr, *tokchr;
	struct pipe_element *pcmd, *cpcmd, *lpcmd;

	retv = 0;
	if (res)
		res[0] = 0;
	if (!cmdline)
		return retv;
	len = strlen(cmdline);
	if (len < 1)
		return retv;
	len = (len / sizeof(char *) + 1) * sizeof(char *);
	buflen = len + MAX_PIPES * sizeof(struct pipe_element);
	cmdbuf = malloc(buflen);
	if (!cmdbuf) {
		elog("Out of Memor\n");
		return -ENOMEM;
	}
	pcmd = (struct pipe_element *)(cmdbuf + len);
	memset(pcmd, 0, MAX_PIPES * sizeof(struct pipe_element));
	strcpy(cmdbuf, cmdline);
	pin = 0;
	pout = 0;
	tokchr = strtok_r(cmdbuf, "|", &saveptr);
	cpcmd = pcmd;
	lpcmd = pcmd + MAX_PIPES;
	sysret = pipe(pipe_fd);
	if (sysret == -1) {
		elog("pipe failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_10;
	}
	pout = pipe_fd[1];
	while (tokchr && cpcmd < lpcmd) {
		cpcmd->cmd = tokchr;
		tokchr = strtok_r(NULL, "|", &saveptr);
		cpcmd->pin = pipe_fd[0];
		sysret = pipe(pipe_fd);
		if (sysret == -1) {
			elog("pipe failed: %s\n", strerror(errno));
			retv = -errno;
			goto exit_10;
		}
		cpcmd->pout = pipe_fd[1];
		cpcmd += 1;
	}
	assert(tokchr == NULL);
	npipes = (cpcmd - pcmd);
	pin = pipe_fd[0];
	for (cpcmd = pcmd, idx = 0; idx < npipes - 1; idx++, cpcmd++) {
		cpcmd->pid = fork();
		if (cpcmd->pid == -1) {
			elog("fork failed: %s\n", strerror(errno));
			retv = -errno;
			goto exit_10;
		}
		if (cpcmd->pid == 0) {
			fclose(stdin);
			stdin = fdopen(dup(cpcmd->pin), "rb");
			fclose(stdout);
			stdout = fdopen(dup(cpcmd->pout), "wb");
			parse_execute(cpcmd->cmd);
		}
	}
	cpcmd->pid = fork();
	if (cpcmd->pid == -1) {
		elog("fork failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_10;
	}
	if (cpcmd->pid == 0) {
		fclose(stdin);
		stdin = fdopen(dup(cpcmd->pin), "rb");
		if (res) {
			fclose(stdout);
			stdout = fdopen(dup(cpcmd->pout), "wb");
			fclose(stderr);
			stderr = fdopen(dup(cpcmd->pout), "wb");
		}
		parse_execute(cpcmd->cmd);
	}

	struct pollfd pfd;
	pfd.fd = pout;
	pfd.events = POLLOUT;
	ln = input;
	while (ln && *ln) {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, 200);
		if (pfd.revents & POLLERR)
			break;
		inlen = strlen(ln);
		len = write(pfd.fd, ln, inlen);
		if (len == -1) {
			elog("Write input through pipe failed: %s\n",
					strerror(errno));
			break;
		} else
			ln += len;
	}

	pfd.fd = pin;
	pfd.events = POLLIN;
	if (res)
		retv = wait_and_get(cpcmd->pid, res, reslen, &pfd, cmdline);
	else {
		do
			sysret = waitpid(cpcmd->pid, &retv, 0);
		while (sysret == -1 && errno == EINTR);
		assert(sysret > 0);
	}
	cpcmd->pid = 0;

exit_10:
	if (pin)
		close(pin);
	if (pout)
		close(pout);
	for (cpcmd = pcmd, idx = 0; idx < npipes; idx++, cpcmd++) {
		if (cpcmd->pin)
			close(cpcmd->pin);
		if (cpcmd->pout)
			close(cpcmd->pout);
		if (cpcmd->pid == 0)
			continue;
		do
			sysret = waitpid(cpcmd->pid, NULL, 0);
		while (sysret == -1 && errno == EINTR);
		if (unlikely(sysret == -1))
			elog("waitpid failed for %s: %s\n", cpcmd->cmd,
					strerror(errno));
	}
	if (unlikely(retv != 0))
		elog("failed command: code %X %s\n--->%s\n", retv, cmdline, res);

	free(cmdbuf);
	return retv;
}
