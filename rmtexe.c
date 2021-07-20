#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include "miscs.h"
#include "pipe_execution.h"

int main(int argc, char *argv[])
{
	int c, fin, rm, reslen, retv;
	const char *peer, *exfile;
	char *res;
	extern char *optarg;
	extern int optind, opterr, optopt;

	rm = 0;
	exfile = NULL;
	peer = NULL;
	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":r:d");
		switch(c) {
		case '?':
			elog("unknown option: %c\n", (char)optopt);
			break;
		case ':':
			elog("missing argument for %c\n", (char)optopt);
			break;
		case 'r':
			peer = optarg;
			break;
		case 'd':
			rm = 1;
			break;
		case -1:
			fin = 1;
			break;
		default:
			assert(0);
		}
	} while (fin == 0);
	if (!peer) {
		elog("The remote host must be specified.\n");
		return 1;
	}
	if (optind < argc)
		exfile = argv[optind];
	if (!exfile) {
		elog("The executable file must be specified.\n");
		return 2;
	}
	
	reslen = 1024;
	res = malloc(reslen);
	retv = scp_execute(res, reslen, peer, exfile, rm);
	if (retv != 0)
		elog("Remote execution failed.\n");
	printf("%s\n", res);
	free(res);
	return retv;
}
