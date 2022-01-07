#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "miscs.h"
#include "pipe_execution.h"

int main(int argc, char *argv[])
{
	int retv = 0;
	char res[1024];

	elog_init();

	retv = pipe_execute(NULL, 0, "ls -l troot|wc", NULL, NULL);
	printf("%s", res);
/*	retv = pipe_execute(res, 1024, "ls -l ytroot", NULL, NULL);
	printf("%s", res);
	if (unlikely(!getcwd(ocwd, sizeof(ocwd)))) {
		elog("Cannot get current directory: %s\n", strerror(errno));
		return 1;
	}
	if (unlikely(chdir("troot") == -1)) {
		elog("Cannot change into troot: %s\n", strerror(errno));
		return 2;
	}
	printf("CWD: %s\n", getcwd(NULL, 0));
	sprintf(cmdbuf, "find . -print|cpio -o -H newc|gzip -c -9");
	retv = pipe_execute("../initramfs.img", 0, cmdbuf, NULL, 1);
	if (unlikely(chdir(ocwd) == -1)) {
		elog("Cannot change back to %s: %s\n", ocwd, strerror(errno));
	}*/

	return retv;
}
