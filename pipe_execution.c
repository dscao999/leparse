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

int pipe_execute(char *res, int reslen, const char *cmdpath,
		const char *cmdline, const char *input)
{
	int sysret, retv, pfdin[2], pfdout[2], idx;
	int fdout, fdin;
	char *curchr, *args[20], *cmdbuf;
	pid_t subpid;
	int numb;

	cmdbuf = malloc(strlen(cmdline)+1);
	if (!cmdbuf) {
		elog("Out of Memory.\n");
		return -100;
	}
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
	idx = 0;
	curchr = strtok(cmdbuf, " ");
	while (curchr && idx < sizeof(args)/sizeof(char *) - 1) {
		args[idx++] = curchr;
		curchr = strtok(NULL, " ");
	}
	args[idx] = NULL;
	subpid = fork();
	if (subpid == -1) {
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
		sysret = execv(cmdpath, args);
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

int scp_execute(char *res, int reslen, const char *ip, const char *fname,
		int rm)
{
	struct stat mst;
	char *cmdbuf, bname[128];
	const char *lsl;
	int sysret, retv = -1;
	static const char *cpfmt = "scp -o BatchMode=yes %s root@%s:";
	static const char *exfmt = "ssh -o BatchMode=yes -l root %s ./%s";
	static const char *rmfmt = "ssh -o BatchMode=yes -l root %s rm ./%s";

	sysret = stat(fname, &mst);
	if (sysret == -1) {
		fprintf(stderr, "No such file %s: %s\n", fname,
				strerror(errno));
		return -errno;
	}
	cmdbuf = malloc(512);
	if (!cmdbuf) {
		fprintf(stderr, "Out of Memory.\n");
		return -100;
	}
	sprintf(cmdbuf, cpfmt, fname, ip);
	retv = pipe_execute(res, reslen, "/usr/bin/scp", cmdbuf, NULL);
	if (retv != 0) {
		elog("%s failed: %s\n", cmdbuf, res);
		goto exit_10;
	}
	lsl = strrchr(fname, '/');
	if (lsl)
		strcpy(bname, lsl+1);
	else
		strcpy(bname, fname);
	sprintf(cmdbuf, exfmt, ip, bname);
	retv = pipe_execute(res, reslen, "/usr/bin/ssh", cmdbuf, NULL);
	if (retv != 0) {
		elog("%s failed: %s\n", cmdbuf, res);
		goto exit_10;
	}
	if (!rm)
		goto exit_10;

	sprintf(cmdbuf, rmfmt, ip, bname);
	retv = pipe_execute(res, reslen, "/usr/bin/ssh", cmdbuf, NULL);
	if (retv)
		elog("%s failed: %s\n", cmdbuf, res);

exit_10:
	free(cmdbuf);
	return retv;
}
