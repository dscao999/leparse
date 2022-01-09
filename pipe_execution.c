#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
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
		retv = pipe_execute(tmpres, MSGLEN, cmdbuf, NULL, 0);
		if (unlikely(retv != 0)) {
			elog("ssh copy failed: %s\n", cmdfile);
			goto exit_10;
		}
		len = sprintf(cmdbuf, exfmt, ip, cmd);
	} else
		len = sprintf(cmdbuf, e0fmt, ip, cmd);
	if (bsl)
		sprintf(cmdbuf+len, "%s", bsl);
	retv = pipe_execute(res, reslen, cmdbuf, input, 0);
	if (unlikely(retv != 0))
		goto exit_10;
	if (!rm || !lsl)
		goto exit_10;

	sprintf(cmdbuf, rmfmt, ip, cmd);
	retv = pipe_execute(tmpres, MSGLEN, cmdbuf, NULL, 0);
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
	int pin, pout, perr;
};

static void close_all(struct pipe_element *pcmd, int npipes)
{
	int idx;
	struct pipe_element *cpcmd;

	for (cpcmd = pcmd, idx = 0; idx < npipes; idx++, cpcmd++) {
		if (likely(cpcmd->pin != -1))
			close(cpcmd->pin);
		close(cpcmd->pout);
		close(cpcmd->perr);
		cpcmd->pin = -1;
		cpcmd->pout = -1;
		cpcmd->perr = -1;
	}
}

static int probe_io(struct pollfd *pfd, int numpfds, const char *input,
		const char **nxin, char *res, int reslen)
{
	int sysret, retv, i, numr, numw, len, numb;
	struct pollfd *cpfd;

	*nxin = input;
	retv = 0;
	for (cpfd = pfd, i = 0; i < numpfds; i++, cpfd++)
		cpfd->revents = 0;
	sysret = poll(pfd, numpfds, 200);
	if (sysret == 0 || (sysret == -1 && errno == EINTR))
		return retv;
	if (sysret == -1) {
		elog("poll failed: %s\n", strerror(errno));
		return sysret;
	}
	numb = 0;
	for (cpfd = pfd, i = 0; i < numpfds; i++, cpfd++) {
		if (cpfd->revents & POLLIN) {
			numr = read(cpfd->fd, res, reslen);
			if (numr == -1) {
				elog("Failed to read: %s\n", strerror(errno));
				return numr;
			}
			numb += numr;
			res += numb;
			reslen -= numb;
			if (reslen)
				*res = 0;
			else
				*(res-1) = 0;
			cpfd->revents ^= POLLIN;
		}
		if (cpfd->revents & POLLOUT) {
			len = strlen(input);
			numw = 0;
			if (len > 0)
				numw = write(cpfd->fd, input, len);
			if (numw == -1) {
				elog("failed to write: %s\n",
						strerror(errno));
				return numw;
			}
			*nxin = input + numw;
			cpfd->revents ^= POLLOUT;
		}
	       	if (cpfd->revents && cpfd->revents != POLLHUP)
			elog("fd: %d, error: %X\n", cpfd->fd, cpfd->revents);
	}
	return numb;
}

int pipe_execute(char *res, int reslen, const char *cmdline, const char *input,
		const char *ofname)
{
	int sysret, retv, pout, pin, poerr, pierr, idx;
	int ofd, *retvs, fin;
	int npipes, buflen, pipe_fd[2], len, lenrem, cmdlen;
	char *cmdbuf, *saveptr, *tokchr, *resbuf;
	const char *input_ptr;
	struct pipe_element *pcmd, *cpcmd, *lpcmd;

	npipes = 0;
	retv = 0;
	pout = -1;
	pin = -1;
	poerr = -1;
	pierr = -1;
	ofd = -1;
	if (res)
		res[0] = 0;
	if (!cmdline)
		return retv;
	len = strlen(cmdline);
	if (len == 0)
		return retv;
	cmdlen = (len / sizeof(char *) + 1) * sizeof(char *);
	buflen = cmdlen + MAX_PIPES * sizeof(struct pipe_element)
		+ MAX_PIPES * sizeof(int *);
	cmdbuf = malloc(buflen);
	if (!cmdbuf) {
		elog("Out of Memor\n");
		return -ENOMEM;
	}
	retv = 0;
	pcmd = (struct pipe_element *)(cmdbuf + cmdlen);
	retvs = (int *)(pcmd + MAX_PIPES);
	for (idx = 0, cpcmd = pcmd; idx < MAX_PIPES; idx++, cpcmd++) {
		cpcmd->pin = -1;
		cpcmd->pout = -1;
		cpcmd->perr = -1;
		cpcmd->pid = 0;
		cpcmd->cmd = NULL;
		*(retvs+idx) = -1;
	}
	cpcmd = pcmd;
	lpcmd = pcmd + MAX_PIPES;
	if (res) {
		sysret = pipe(pipe_fd);
		if (unlikely(sysret == -1)) {
			elog("pipe failed: %s\n", strerror(errno));
			retv = -errno;
			goto exit_10;
		}
		pierr = pipe_fd[0];
		poerr = pipe_fd[1];
	} else {
		poerr = dup(fileno(stderr));
		if (unlikely(poerr == -1)) {
			elog("dup failed: %s\n", strerror(errno));
			retv = -errno;
			goto exit_10;
		}
	}
	sysret = pipe(pipe_fd);
	if (unlikely(sysret == -1)) {
		elog("pipe failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_10;
	}
	pout = pipe_fd[1];
	strcpy(cmdbuf, cmdline);
	tokchr = strtok_r(cmdbuf, "|", &saveptr);
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
		cpcmd->perr = dup(poerr);
		if (unlikely(cpcmd->perr == -1)) {
			elog("dup failed: %s\n", strerror(errno));
			retv = -errno;
			goto exit_10;
		}
		cpcmd += 1;
	}
	assert(tokchr == NULL);
	npipes = (cpcmd - pcmd);
	pin = pipe_fd[0];
	close(poerr);
	poerr = -1;
	cpcmd = pcmd + npipes - 1;
	if (!res) {
		close(pin);
		pin = -1;
		close(cpcmd->pout);
		cpcmd->pout = dup(fileno(stdout));
		if (unlikely(cpcmd->pout == -1)) {
			elog("dup failed: %s\n", strerror(errno));
			retv = -errno;
			goto exit_10;
		}
	}
	if (ofname) {
		ofd = open(ofname, O_WRONLY|O_CREAT, 0644);
		if (unlikely(ofd == -1)) {
			elog("Cannot open file %s: %s\n", ofname,
					strerror(errno));
			goto exit_10;
		}
		if (pin != -1) {
			close(pin);
			pin = -1;
		}
		close(cpcmd->pout);
		cpcmd->pout = dup(ofd);
		if (unlikely(cpcmd->pout == -1)) {
			elog("dup failed: %s\n", strerror(errno));
			retv = -errno;
			goto exit_10;
		}
		close(ofd);
		ofd = -1;
	}
	if (!input) {
		close(pout);
		pout = -1;
		close(pcmd->pin);
		pcmd->pin = -1;
	}

	for (cpcmd = pcmd, idx = 0; idx < npipes; idx++, cpcmd++) {
		cpcmd->pid = fork();
		if (cpcmd->pid == -1) {
			elog("fork failed: %s\n", strerror(errno));
			retv = -errno;
			goto exit_10;
		}
		if (cpcmd->pid == 0) {
			fclose(stdout);
			stdout = fdopen(dup(cpcmd->pout), "wb");
			fclose(stderr);
			stderr = fdopen(dup(cpcmd->perr), "wb");
			fclose(stdin);
			if (likely(cpcmd->pin != -1))
				stdin = fdopen(dup(cpcmd->pin), "rb");
			close_all(pcmd, npipes);
			if (pin != -1)
				close(pin);
			if (pout != -1)
				close(pout);
			if (pierr != -1)
				close(pierr);
			assert(poerr == -1);
			parse_execute(cpcmd->cmd);
		}
	}

	for (cpcmd = pcmd, idx = 0; idx < npipes; idx++, cpcmd++) {
		if (likely(cpcmd->pin != -1))
			close(cpcmd->pin);
		close(cpcmd->pout);
		close(cpcmd->perr);
		cpcmd->pin = -1;
		cpcmd->pout = -1;
		cpcmd->perr = -1;
	}

	struct pollfd pfd[3];
	int numpfds = 0;
	static const struct timespec itv = {.tv_sec = 0, .tv_nsec = 200000000};

	if (pout != -1) {
		pfd[numpfds].fd = pout;
		pfd[numpfds].events = POLLOUT;
		numpfds++;
	}
	if (pierr != -1) {
		pfd[numpfds].fd = pierr;
		pfd[numpfds].events = POLLIN;
		numpfds++;
	}
	if (pin != -1) {
		pfd[numpfds].fd = pin;
		pfd[numpfds].events = POLLIN;
		numpfds++;
	}

	resbuf = res;
	lenrem = reslen;
	do {
		if (numpfds > 0) {
			if (lenrem <= 0) {
				elog("Output Buffer Overflow\n");
				resbuf = res;
				lenrem = reslen;
			}
			retv = probe_io(pfd, numpfds, input, &input_ptr,
					resbuf, lenrem);
			if (retv == -1)
				break;
			resbuf += retv;
			lenrem -= retv;
			input = input_ptr;
		} else
			op_nanosleep(&itv);
		fin = 1;
		for (cpcmd = pcmd, idx = 0; idx < npipes; idx++, cpcmd++) {
			if (cpcmd->pid == 0)
				continue;
			fin = 0;
			sysret = waitpid(cpcmd->pid, retvs+idx, WNOHANG);
			if (sysret > 0)
				cpcmd->pid = 0;
		}
	} while (fin == 0);

exit_10:
	if (ofd != -1)
		close(ofd);
	if (pin != -1)
		close(pin);
	if (pout != -1)
		close(pout);
	if (pierr != -1)
		close(pierr);
	if (poerr != -1)
		close(poerr);
	for (cpcmd = pcmd, idx = 0; idx < MAX_PIPES; idx++, cpcmd++) {
		if (cpcmd->pin != -1)
			close(cpcmd->pin);
		if (cpcmd->pout != -1)
			close(cpcmd->pout);
		if (cpcmd->perr != -1)
			close(cpcmd->perr);
		if (cpcmd->pid == 0)
			continue;
		do
			sysret = waitpid(cpcmd->pid, retvs+idx, 0);
		while (sysret == -1 && errno == EINTR);
		if (unlikely(sysret == -1))
			elog("waitpid failed for %s: %s\n", cpcmd->cmd,
					strerror(errno));
	}
	for (idx = MAX_PIPES - 1; idx >= 0; idx--) {
		retv = *(retvs+idx);
		if (retv != -1)
			break;
	}
	if (unlikely(retv != 0))
		elog("failed command: code %X %s\n--->%s\n", retv, cmdline, res);

	free(cmdbuf);
	return retv;
}
