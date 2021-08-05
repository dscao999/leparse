#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include "miscs.h"
#include "pipe_execution.h"

int pipe_execute(char *res, int reslen, const char *cmdline, const char *input)
{
	int sysret, retv, pfdin[2], pfdout[2], idx;
	int fdout, fdin, numargs, cmdlen;
	char *curchr, **args, *cmdbuf, *cmd;
	char *lsl;
	pid_t subpid;
	int numb, len;

	retv = -1;
	if (!cmdline)
		return retv;
	len = strlen(cmdline);
	if (len < 1)
		return retv;
	cmdlen = ((len - 1) / sizeof(char *) + 1) * sizeof(char *);
	numargs = 20;
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
	curchr = strtok(cmdbuf, " ");
	strcpy(cmd, curchr);
	lsl = strrchr(curchr, '/');
	idx = 0;
	while (curchr && idx < numargs - 1) {
		args[idx++] = curchr;
		curchr = strtok(NULL, " ");
	}
	args[idx] = NULL;
	if (lsl)
		args[0] = lsl + 1;
	subpid = fork();
	if (unlikely(subpid == -1)) {
		fprintf(stderr, "fork failed: %s\n", strerror(errno));
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
		if (lsl)
			sysret = execv(cmd, args);
		else
			sysret = execvp(cmd, args);
		if (sysret == -1)
			fprintf(stderr, "execv failed: %s\n", strerror(errno));
		exit(1);
	}
	fdout = pfdout[1];
	fdin = pfdin[0];
	if (input) {
		numb = write(fdout, input, strlen(input));
		if (numb == -1)
			fprintf(stdout, "Write input through pipe failed: %s\n",
					strerror(errno));
	}
	sysret = waitpid(subpid, &retv, 0);
	struct pollfd pfd;
	pfd.fd = fdin;
	pfd.events = POLLIN;
	pfd.revents = 0;
	numb = 0;
	sysret = poll(&pfd, 1, 100);
	if (sysret == 1 && (pfd.revents & POLLIN) != 0)
		numb = read(fdin, res, reslen - 1);
	*(res+numb) = 0;
	if (retv != 0)
		fprintf(stderr, "execution failed, command: %s\nresponse: %s\n",
				cmdline, res);

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
		int rm)
{
	struct stat mst;
	char *cmdbuf, **args, *curchr, *cmdfile, *cmdexe; 
	char *lsl;
	int sysret, retv = -1, cmdlen, numargs, idx;
	int pntpos, pntlen, len;
	static const char *cpfmt = "scp -o BatchMode=yes %s root@%s:";
	static const char *exfmt = "ssh -o BatchMode=yes -l root %s ./%s";
	static const char *e0fmt = "ssh -o BatchMode=yes -l root %s %s";
	static const char *rmfmt = "ssh -o BatchMode=yes -l root %s rm ./%s";

	if (!cmdline)
		return retv;
	len = strlen(cmdline);
	if (len < 1)
		return retv;
	numargs = 20;
	cmdlen = ((len - 1) / sizeof(char *) + 1) * sizeof(char *);
	cmdbuf = malloc(2*cmdlen + sizeof(char *)*numargs + 128);
	if (!cmdbuf) {
		fprintf(stderr, "Out of Memory.\n");
		return -100;
	}
	args = (char **)(cmdbuf + cmdlen);
	cmdexe = (char *)(args + numargs);
	strcpy(cmdbuf, cmdline);
	curchr = strtok(cmdbuf, " ");
	idx = 0;
	while (curchr) {
		args[idx++] = curchr;
		curchr = strtok(NULL, " ");
	}
	args[idx] = curchr;

	pntpos = 0;
	cmdfile = args[0];
	lsl = strrchr(cmdfile, '/');
	if (lsl) {
		sysret = stat(cmdfile, &mst);
		if (sysret == -1) {
			fprintf(stderr, "No such file %s: %s\n", cmdfile,
					strerror(errno));
			retv = -errno;
			goto exit_10;
		}
		sprintf(cmdexe, cpfmt, cmdfile, ip);
		retv = pipe_execute(res, reslen, cmdexe, NULL);
		if (retv != 0) {
			elog("%s failed: %s\n", cmdexe, res);
			goto exit_10;
		}
		args[0] = lsl + 1;
		pntlen = sprintf(cmdexe, exfmt, ip, args[0]);
		pntpos += pntlen;
	} else {
		pntlen = sprintf(cmdexe, e0fmt, ip, args[0]);
		pntpos += pntlen;
	}
	for (idx = 1; args[idx]; idx++) {
		pntlen = sprintf(cmdexe+pntpos, " %s", args[idx]);
		pntpos += pntlen;
	}
	retv = pipe_execute(res, reslen, cmdexe, NULL);
	if (retv != 0) {
		elog("%s failed: %s\n", cmdexe, res);
		goto exit_10;
	}
	if (!rm || !lsl)
		goto exit_10;

	sprintf(cmdexe, rmfmt, ip, args[0]);
	retv = pipe_execute(cmdbuf, cmdlen, cmdexe, NULL);
	if (retv)
		elog("%s failed: %s\n", cmdexe, cmdbuf);

exit_10:
	free(cmdbuf);
	return retv;
}
