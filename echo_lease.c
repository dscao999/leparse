#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

static volatile int global_exit = 0;

void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

int main(int argc, char *argv[])
{
	struct sigaction mact;
	struct addrinfo hint, *svrinfo, *adr;
	int retv, sock, eno, buflen, fin, c;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	ssize_t nread;
	char *buf;
	const char *port = "7800";
	extern char *optarg;
	extern int opterr, optopt;

	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":p:");
		switch (c) {
		case -1:
			fin = 1;
			break;
		case '?':
			fprintf(stderr, "Unknown option: %c\n", optopt);
			break;
		case ':':
			fprintf(stderr, "Missing arguments for %c\n",
					(char)optopt);
			break;
		case 'p':
			port = optarg;
			break;
		default:
			assert(0);
		}
	} while (fin == 0);
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_flags = AI_PASSIVE|AI_NUMERICSERV;
	retv = getaddrinfo(NULL, port, &hint, &svrinfo);
	if (retv != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(retv));
		return 1;
	}
	for (adr = svrinfo; adr != NULL; adr = adr->ai_next) {
		sock = socket(adr->ai_family, adr->ai_socktype,
				adr->ai_protocol);
		if (sock == -1)
			continue;

		retv = bind(sock, adr->ai_addr, adr->ai_addrlen);
		eno = errno;
		if (retv == 0)
			break;
		close(sock);
	}
	freeaddrinfo(svrinfo);
	if (adr == NULL) {
		fprintf(stderr, "Cannot bind: %s.\n", strerror(eno));
		return 2;
	}

	memset(&mact, 0, sizeof(mact));
	mact.sa_handler = sig_handler;
	if (sigaction(SIGINT, &mact, NULL) == -1 ||
			sigaction(SIGTERM, &mact, NULL) == -1)
		fprintf(stderr, "Warning: cannot install signal handler: %s\n",
				strerror(errno));

	buflen = 512;
	buf = malloc(buflen);
	retv = 0;
	while (global_exit == 0) {
		peer_addr_len = sizeof(struct sockaddr_storage);
		nread = recvfrom(sock, buf, buflen, 0,
				(struct sockaddr *)&peer_addr, &peer_addr_len);
		if (nread == -1 && errno != EINTR) {
			fprintf(stderr, "recvfrom failed: %s\n",
					strerror(errno));
			retv = 5;
			goto exit_10;
		}
		if (nread > 0) {
			buf[nread] = 0;
			printf("%s\n", buf);
		}
	}

exit_10:
	free(buf);
	close(sock);
	return retv;
}
