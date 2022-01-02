#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include "miscs.h"
#include "pipe_execution.h"

int verbose = 0;

int main(int argc, char *argv[])
{
	int c, fin, rm, retv;
	const char *peer, *exfile;
	char *cmdline;
	int i, pntpos, pntlen;
	extern char *optarg;
	extern int optind, opterr, optopt;

	rm = 0;
	exfile = NULL;
	peer = NULL;
	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":r:dv");
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
		case 'v':
			verbose = 1;
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
	elog_init();
	
	cmdline = malloc(1024);
	pntpos = 0;
	for (i = optind; i < argc; i++) {
		pntlen = sprintf(cmdline+pntpos, " %s", argv[i]);
		pntpos += pntlen;
	}
	retv = ssh_execute(NULL, 0, peer, cmdline, NULL, rm);
	if (retv != 0)
		elog("Remote execution failed.\n");
	free(cmdline);
	return retv;
}
