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
#include <time.h>
#include "miscs.h"
#include "dbproc.h"

struct thread_worker {
	struct lease_info *inf;
	volatile int *nwork;
};

#define maxeles 1024
#define maxmask 1023

struct cirbuf {
	volatile int head;
	volatile int tail;
	volatile int *global_exit;
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

static inline void cirbuf_init(struct cirbuf *cbuf, volatile int *global_exit)
{
	cbuf->head = 0;
	cbuf->tail = 0;
	cbuf->global_exit = global_exit;
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
	pthread_mutex_lock(&cbuf->mutex);
	if (cirbuf_empty(cbuf))
		wake = 1;
	cbuf->linfs[cbuf->head] = inf;
	cbuf->head = cirbuf_head_next(cbuf);
	if (wake)
		pthread_cond_signal(&cbuf->cond);
	pthread_mutex_unlock(&cbuf->mutex);
	return 0;
}

static inline struct lease_info * cirbuf_remove(struct cirbuf *cbuf)
{
	struct lease_info *inf;
	time_t tm;

	inf = NULL;
	pthread_mutex_lock(&cbuf->mutex);
	while (cirbuf_empty(cbuf))
		pthread_cond_wait(&cbuf->cond, &cbuf->mutex);
	assert(cirbuf_empty(cbuf) == 0);
	tm = time(NULL);
	inf = cbuf->linfs[cbuf->tail];
	if (tm - inf->stm > 2)
		cbuf->tail = cirbuf_tail_next(cbuf);
	else
		inf = NULL;
	pthread_mutex_unlock(&cbuf->mutex);
	return inf;
}

static volatile int global_exit = 0;

void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

void * check_mandb(void *dat)
{
	struct thread_worker *me = (struct thread_worker *)dat;
	struct lease_info *inf = me->inf;
	int retv;
	volatile int *nwrk;

	nwrk = me->nwork;
	retv = dbproc(inf);
	if (retv)
		elog("Somethin wrong in DB processing.\n");
	free(inf);
	free(me);
	__sync_sub_and_fetch(nwrk, 1);
	return NULL;
}

void * echo_processing(void *dat)
{
	struct cirbuf *wbuf = (struct cirbuf *)dat;
	struct lease_info *inf;
	pthread_t ckthrd;
	pthread_attr_t attr;
	int sysret;
	volatile int nworker;
	struct thread_worker *thwork;
	static const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};

	nworker = 0;
	sysret = pthread_attr_init(&attr);
	if (sysret) {
		elog("Cannot initialize thread attr: %s\n",
				strerror(sysret));
		global_exit = 1;
		return NULL;
	}
	sysret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (sysret) {
		elog("Cannot set thread to detached: %s\n",
				strerror(sysret));
		global_exit = 1;
		goto exit_10;
	}
	do {
		inf = cirbuf_remove(wbuf);
		if (!inf) {
			nanosleep(&itv, NULL);
			continue;
		}
		if (inf->mac[0] == 0)
			continue;

		thwork = malloc(sizeof(struct thread_worker));
		if (!thwork) {
			elog("Out of Memory.\n");
			global_exit = 1;
			free(inf);
			goto exit_10;
		}
		thwork->inf = inf;
		thwork->nwork = &nworker;
		sysret = pthread_create(&ckthrd, &attr, check_mandb, thwork);
		if (sysret) {
			elog("Cannot create worker thread: %s\n",
					strerror(sysret));
			global_exit = 1;
			free(inf);
			free(thwork);
			goto exit_10;
		}
		__sync_add_and_fetch(&nworker, 1);
	} while (global_exit == 0);

exit_10:
	pthread_attr_destroy(&attr);
	while (nworker) {
		printf("nworker: %d\n", nworker);
		nanosleep(&itv, NULL);
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	struct sigaction mact;
	struct addrinfo hint, *svrinfo, *adr;
	int retv, sock, eno, buflen, fin, c, leave;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	ssize_t nread;
	char *buf, *tok, *ip, *start, *mac;
	const char *port = "7800";
	struct cirbuf *wbuf;
	struct lease_info *linfo;
	time_t tm;
	static const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};
	extern char *optarg;
	extern int opterr, optopt;
	pthread_t echo_thread;
	static struct lease_info fake_inf;

	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":p:");
		switch (c) {
		case -1:
			fin = 1;
			break;
		case '?':
			elog("Unknown option: %c\n", optopt);
			break;
		case ':':
			elog("Missing arguments for %c\n",
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
		elog("getaddrinfo failed: %s\n", gai_strerror(retv));
		return 1;
	}
	eno = 0;
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
		elog("Cannot bind: %s.\n", strerror(eno));
		return 2;
	}

	memset(&mact, 0, sizeof(mact));
	mact.sa_handler = sig_handler;
	if (sigaction(SIGINT, &mact, NULL) == -1 ||
			sigaction(SIGTERM, &mact, NULL) == -1)
		elog("Warning: cannot install signal handler: %s\n",
				strerror(errno));

	buflen = 512;
	buf = malloc(buflen+sizeof(struct cirbuf));
	wbuf = (struct cirbuf *)(buf + buflen);
	cirbuf_init(wbuf, &global_exit);

	retv = pthread_create(&echo_thread, NULL, echo_processing, wbuf);
	if (retv) {
		elog("Cannot create echo processing thread: %s\n",
				strerror(retv));
		goto exit_20;
	}
	retv = 0;
	while (global_exit == 0) {
		peer_addr_len = sizeof(struct sockaddr_storage);
		nread = recvfrom(sock, buf, buflen, 0,
				(struct sockaddr *)&peer_addr, &peer_addr_len);
		if (nread == -1 && errno != EINTR) {
			elog("recvfrom failed: %s\n",
					strerror(errno));
			retv = 5;
			goto exit_20;
		}
		if (nread <= 0)
			continue;
		buf[nread] = 0;
		printf("%s\n", buf);

		tok = strtok(buf, " ;{}");
		leave = strcmp(buf, "leave") == 0;
		if (strcmp(buf, "lease") != 0 && !leave)
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
			elog("Out of Memory.\n");
			global_exit = 1;
			break;
		}
		linfo->tm = tm;
		linfo->leave = leave;
		linfo->stm = time(NULL);
		strcpy(linfo->mac, mac);
		strcpy(linfo->ip, ip);
		if (cirbuf_search(wbuf, linfo))
			continue;
		while (cirbuf_insert(wbuf, linfo) == -1) {
			elog("Stall for one second.\n");
			nanosleep(&itv, NULL);
		}
	}
	if (cirbuf_empty(wbuf)) {
		linfo = &fake_inf;
		linfo->stm = time(NULL) - 5;
		linfo->mac[0] = 0;
		cirbuf_insert(wbuf, linfo);
	}
	printf("exit...\n");
	pthread_join(echo_thread, NULL);

exit_20:
	while (!cirbuf_empty(wbuf)) {
		linfo = cirbuf_remove(wbuf);
		free(linfo);
	}
	cirbuf_exit(wbuf);
	free(buf);
	close(sock);
	return retv;
}
