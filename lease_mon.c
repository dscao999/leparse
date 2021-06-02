#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "file_monitor.h"
#include "lease_parse.h"

static volatile int global_exit = 0;

off_t read_tail(const struct file_watch *fw)
{
	FILE *fin;
	struct dhclient_lease *lebuf;
	int len;

	fin = fopen(fw->lfile, "r");
	if (!fin) {
		fprintf(stderr, "Cannot open %s: %s\n", fw->lfile,
				strerror(errno));
		return fw->offset;
	}
	if (fseek(fin, fw->offset, SEEK_SET) == -1) {
		fprintf(stderr, "Cannot fseek to the position: %s\n",
				strerror(errno));
		return fw->offset;
	}
	lebuf = dhclient_init(1024);
	if (!lebuf) {
		fprintf(stderr, "Out of Memory.\n");
		fclose(fin);
		exit(100);
	}

	do {
		len = dhclient_lease_parse(fin, lebuf);
		if (len > 0)
			printf("%s\n", lebuf->rec);
	} while (len != -1);

	dhclient_exit(lebuf);

	return ftell(fin);
}

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

	monitor_set_action(fw, read_tail);
	do {
		retv = monitor_watch(fw);
	} while (retv > 0 && global_exit == 0);

	retv = 0;

	monitor_exit(fw);
exit_10:
	free(fw);
	return retv;
}
