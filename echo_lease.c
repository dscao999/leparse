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
#include <pthread.h>

struct lease_info {
	char mac[24];
	char ip[64];
	time_t tm;
};

#define maxeles 1024
#define maxmask 1023

struct cirbuf {
	volatile int head;
	volatile int tail;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	struct lease_info *linfs[maxeles];
};

static int cirbuf_search(struct cirbuf *cbuf, struct lease_info *linf)
{
	int idx, found = 0;

	pthread_mutex_lock(&cbuf->mutex);
	for (idx = cbuf->tail; idx != cbuf->head; idx = (idx + 1) & maxmask) {
		if (linf->tm != cbuf->linfs[idx]->tm)
			continue;
		if (strcmp(linf->mac, cbuf->linfs[idx]->mac) == 0) {
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&cbuf->mutex);
	return found;
}

static inline void cirbuf_init(struct cirbuf *cbuf)
{
	cbuf->head = 0;
	cbuf->tail = 0;
	pthread_cond_init(&cbuf->cond, NULL);
	pthread_mutex_init(&cbuf->mutex, NULL);
}

static inline void cirbuf_exit(struct cirbuf *cbuf)
{
	pthread_cond_destroy(&cbuf->cond);
	pthread_mutex_destroy(&cbuf->mutex);
}

static inline int cirbuf_head_next(const struct cirbuf *cbuf)
{
	return (cbuf->head + 1) & maxmask;
}

static inline int cirbuf_tail_next(const struct cirbuf *cbuf)
{
	return (cbuf->tail + 1) & maxmask;
}

static inline int cirbuf_empty(const struct cirbuf *cbuf)
{
	return (cbuf->head == cbuf->tail);
}

static inline int cirbuf_full(const struct cirbuf *cbuf)
{
	return (cirbuf_head_next(cbuf) == cbuf->tail);
}

static inline int cirbuf_insert(struct cirbuf *cbuf, struct lease_info *inf)
{
	int wake = 0;

	if (cirbuf_full(cbuf))
		return -1;
	if (cirbuf_empty(cbuf))
		wake = 1;
	cbuf->linfs[cbuf->head] = inf;
	cbuf->head = cirbuf_head_next(cbuf);
	if (wake) {
		pthread_mutex_lock(&cbuf->mutex);
		pthread_cond_signal(&cbuf->cond);
		pthread_mutex_unlock(&cbuf->mutex);
	}
	return 0;
}

static inline struct lease_info * cirbuf_remove(struct cirbuf *cbuf)
{
	struct lease_info *inf;

	pthread_mutex_lock(&cbuf->mutex);
	while (cirbuf_empty(cbuf))
		pthread_cond_wait(&cbuf->cond, &cbuf->mutex);
	inf = cbuf->linfs[cbuf->tail];
	cbuf->tail = cirbuf_tail_next(cbuf);
	pthread_mutex_unlock(&cbuf->mutex);
	return inf;
}

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
	char *buf, *tok, *ip, *start, *mac;
	const char *port = "7800";
	struct cirbuf *wbuf, *rbuf;
	struct lease_info *linfo;
	time_t tm;
	const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};
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
	buf = malloc(buflen+2*sizeof(struct cirbuf));
	wbuf = (struct cirbuf *)(buf + buflen);
	cirbuf_init(wbuf);
	rbuf = wbuf + 1;
	cirbuf_init(rbuf);

	retv = 0;
	while (global_exit == 0) {
		peer_addr_len = sizeof(struct sockaddr_storage);
		nread = recvfrom(sock, buf, buflen, 0,
				(struct sockaddr *)&peer_addr, &peer_addr_len);
		if (nread == -1 && errno != EINTR) {
			fprintf(stderr, "recvfrom failed: %s\n",
					strerror(errno));
			retv = 5;
			goto exit_20;
		}
		if (nread <= 0)
			continue;
		buf[nread] = 0;
		printf("%s\n", buf);

		tok = strtok(buf, " ;{}");
		if (strcmp(buf, "lease") != 0)
			continue;
		ip = strtok(NULL, " ;{}");
		tok = strtok(NULL, " ;{}");
		if (strcmp(tok, "start") != 0)
			continue;
		start = strtok(NULL, " ;{}");
		tm = atoll(start);
		tok = strtok(NULL, " ;{}");
		if (strcmp(tok, "hardware") != 0)
			continue;
		tok = strtok(NULL, " ;{}");
		if (strcmp(tok, "ethernet") != 0)
			continue;
		mac = strtok(NULL, " ;{}");
		linfo = malloc(sizeof(struct lease_info));
		if (!linfo) {
			fprintf(stderr, "Out of Memory.\n");
			global_exit = 1;
			break;
		}
		linfo->tm = tm;
		strcpy(linfo->mac, mac);
		strcpy(linfo->ip, ip);
		if (cirbuf_search(rbuf, linfo) || cirbuf_search(wbuf, linfo))
			continue;
		while (cirbuf_insert(wbuf, linfo) == -1) {
			fprintf(stderr, "Stall for one second.\n");
			nanosleep(&itv, NULL);
		}
	}
	printf("exit...\n");

exit_20:
	cirbuf_exit(rbuf);
	cirbuf_exit(wbuf);
	free(buf);
	close(sock);
	return retv;
}
