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
	char res[1024], ocwd[128];
	char cmdbuf[256];

	elog_init();

	*res = 0;
	if (unlikely(!getcwd(ocwd, sizeof(ocwd)))) {
		elog("Cannot get current directory: %s\n", strerror(errno));
		return 1;
	}
	if (unlikely(chdir("troot") == -1)) {
		elog("Cannot change into troot: %s\n", strerror(errno));
		return 2;
	}
	printf("CWD: %s\n", getcwd(NULL, 0));
	sprintf(cmdbuf, "find . -print|cpio -o -H newc|gzip -c");
	retv = pipe_execute(NULL, 0, cmdbuf, NULL, "/tmp/initramfs.img");
	if (unlikely(chdir(ocwd) == -1)) {
		elog("Cannot change back to %s: %s\n", ocwd, strerror(errno));
	}

	return retv;
}
