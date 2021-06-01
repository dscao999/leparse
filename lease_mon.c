#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include "file_monitor.h"
#include "lease_parse.h"

static volatile int global_exit = 0;

int main(int argc, char *argv[])
{
	int fin, c, retv;
	const char *lease_file = NULL;
	extern char *optarg;
	extern int optind, opterr, optopt;
	struct file_watch *fw;

	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":l:");
		switch(c) {
		case -1:
			fin = 1;
			break;
		case '?':
			fprintf(stderr, "Unknown option: %c\n", (char)optopt);
			break;
		case ':':
			fprintf(stderr, "Missing arguments for %c\n",
					(char)optopt);
			break;
		case 'l':
			lease_file = optarg;
			break;
		default:
			assert(0);
		}
	} while (fin == 0);
	if (lease_file == NULL)
		lease_file = "/var/lib/dhcp/dhcpd.leases";

	fw = malloc(sizeof(struct file_watch));
	if (!fw) {
		fprintf(stderr, "Out of Memory.\n");
		return 100;
	}
	if (monitor_init(lease_file, fw) < 0) {
		fprintf(stderr, "Cannot Initialize file monitor.\n");
		retv = 1;
		goto exit_10;
	}

	do {
		retv = monitor_watch(fw);
	} while (retv > 0 && global_exit == 0);

	retv = 0;

	monitor_exit(fw);
exit_10:
	free(fw);
	return retv;
}
