#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "file_monitor.h"
#include "lease_parse.h"

static volatile int global_exit = 0;

static void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

struct leserv {
	int sock;
	socklen_t addr_len;
	struct sockaddr addr;
};

off_t read_tail(const struct file_watch *fw, void *data)
{
	FILE *fin;
	struct dhclient_lease *lebuf;
	int len, sysret;
	struct stat mst;
	off_t curpos;
	struct leserv *svr = data;

	fin = fopen(fw->lfile, "r");
	if (!fin) {
		fprintf(stderr, "Cannot open %s: %s\n", fw->lfile,
				strerror(errno));
		return fw->offset;
	}
	sysret = fstat(fileno(fin), &mst);
	assert(sysret == 0);
	if (mst.st_size == 0) {
		fprintf(stderr, "file truncated to zero.\n");
		goto exit_10;
	}

	if (mst.st_size > fw->offset) {
		sysret = fseek(fin, fw->offset, SEEK_SET);
		if (sysret == -1) {
			fprintf(stderr, "Cannot fseek to the position: %s\n",
					strerror(errno));
			exit(11);
		}
	} else {
		fprintf(stderr, "File %s: truncated. Size: %ld\n",
				fw->lfile, mst.st_size);
	}

	lebuf = dhclient_init(1024);
	if (!lebuf) {
		fprintf(stderr, "Out of Memory.\n");
		fclose(fin);
		exit(100);
	}

	do {
		len = dhclient_lease_parse(fin, lebuf);
		if (len <= 0)
			continue;
		if (svr) {
			do {
				sysret = sendto(svr->sock, lebuf->rec, len + 1,
						0, &svr->addr, svr->addr_len);
			} while (sysret == -1 && errno == EINTR);
			if (sysret == -1 && errno != EINTR)
				fprintf(stderr, "sendto failed: %s\n",
						strerror(errno));
		} else {
			printf("%s\n", lebuf->rec);
		}
	} while (len != -1);

	dhclient_exit(lebuf);

exit_10:
	curpos = ftell(fin);
	fclose(fin);

	return curpos;
}

int main(int argc, char *argv[])
{
	int fin, c, retv;
	const char *lease_file = NULL, *server = "127.0.0.1";
	const char *port = "7800";
	extern char *optarg;
	extern int optind, opterr, optopt;
	struct file_watch *fw;
	struct sigaction mact;
	struct leserv serv;
	struct addrinfo hint, *serv_adr;

	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":l:s:p:");
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
		case 's':
			server = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		default:
			assert(0);
		}
	} while (fin == 0);
	if (lease_file == NULL)
		lease_file = "/var/lib/dhcp/dhcpd.leases";

	memset(&mact, 0, sizeof(struct sigaction));
	mact.sa_handler = sig_handler;
	if (sigaction(SIGINT, &mact, NULL) == -1 ||
			sigaction(SIGTERM, &mact, NULL) == -1)
		fprintf(stderr, "Warning: Signal Handler Installation failed:" \
				" %s\n", strerror(errno));

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

	memset(&serv, 0, sizeof(serv));
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_flags = AI_NUMERICSERV;
	retv = getaddrinfo(server, port, &hint, &serv_adr);
	if (retv != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(retv));
		retv = 2;
		goto exit_20;
	}
	serv.addr_len = serv_adr->ai_addrlen;
	memcpy(&serv.addr, serv_adr->ai_addr, serv_adr->ai_addrlen);
	freeaddrinfo(serv_adr);

	serv.sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (serv.sock == -1) {
		fprintf(stderr, "Cannot create socket: %s\n", strerror(errno));
		retv = 3;
		goto exit_20;
	}

	monitor_set_action(fw, read_tail, &serv);
	do {
		retv = monitor_watch(fw);
	} while (retv >= 0 && global_exit == 0);

	close(serv.sock);
exit_20:
	monitor_exit(fw);
exit_10:
	free(fw);
	return retv;
}
