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
#include "list_head.h"
#include "cpuinfo.h"
#include "dbproc.h"

static int verbose = 0;

struct thread_worker {
	struct lease_info inf;
	pthread_t thid;
	struct list_head lst;
	int fin;
	volatile int *w_count;
};

static inline int worker_equal(const struct thread_worker *w1,
		const struct thread_worker *w2)
{
	return (w1->inf.tm == w2->inf.tm) &&
			(strcmp(w1->inf.mac, w2->inf.mac) == 0) &&
			 (w1->inf.leave == w2->inf.leave);
}

static inline void time_add(struct timespec *ltm, const struct timespec *rtm)
{
	ltm->tv_sec += rtm->tv_sec;
	ltm->tv_nsec += rtm->tv_nsec;
	if (ltm->tv_nsec > 999999999l) {
		ltm->tv_sec += 1;
		ltm->tv_nsec -= 1000000l;
	}
}

static void op_nanosleep(const struct timespec *tm)
{
	struct timespec abstm;
	int sysret;

	clock_gettime(CLOCK_MONOTONIC_COARSE, &abstm);
	time_add(&abstm, tm);
	do {
		sysret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &abstm, NULL);
		if (sysret == -1 && errno != EINTR) {
			elog("clock_nanosleep failed: %s\n", strerror(errno));
			break;
		}
	} while (sysret == -1);
}

static volatile int global_exit = 0;

void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

void * process_echo(void *dat)
{
	struct thread_worker *me = (struct thread_worker *)dat;
	int retv;
	time_t tm;
	static const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};

	retv = dbproc(&me->inf);
	atomic_dec(me->w_count);
	if (retv)
		elog("Somethin wrong in lease processing.\n");
	tm = time(NULL);
	while (tm - me->inf.tm < 3) {
		op_nanosleep(&itv);
		tm = time(NULL);
	}
	me->fin = -1;
	return NULL;
}

static int lease_parse(const char *info, struct lease_info *linfo)
{
	char *buf, *tok, *ip, *start, *mac;
	int retv = 0, len, leave;
	long tm;
	static const char *token = " ;{}";

	len = strlen(info);
	buf = malloc(len+1);
	if (!buf) {
		elog("Out of Memory");
		return -1;
	}
	strcpy(buf, info);
	tok = strtok(buf, token);
	leave = strcmp(tok, "leave") == 0;
	if (strcmp(tok, "lease") != 0 && !leave)
		goto exit_10;
	ip = strtok(NULL, token);
	tok = strtok(NULL, token);
	if (strcmp(tok, "start") != 0)
		goto exit_10;
	start = strtok(NULL, token);
	tm = atoll(start);
	tok = strtok(NULL, token);
	if (strcmp(tok, "hardware") != 0)
		goto exit_10;
	tok = strtok(NULL, token);
	if (strcmp(tok, "ethernet") != 0)
		goto exit_10;
	mac = strtok(NULL, token);
	linfo->tm = tm;
	linfo->leave = leave;
	strcpy(linfo->mac, mac);
	strcpy(linfo->ip, ip);
	retv = len;

exit_10:
	free(buf);
	return retv;
}

static void dump_worker(const struct thread_worker *worker)
{
	elog("Number of works: %d, status: %d\n", *worker->w_count, worker->fin);
	dump_list_head(&worker->lst);
	dump_lease_info(&worker->inf);
}

int main(int argc, char *argv[])
{
	struct sigaction mact;
	struct addrinfo hint, *svrinfo;
	int retv, sock, buflen, fin, c;
	int numcpus = 0, sysret;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	ssize_t nread;
	char *buf;
	const char *port = "7800";
	int nworker = 0;
	volatile int w_count = 0;
	struct list_head threads;
	struct thread_worker *worker, *wentry, *nxtw;
	static const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};
	extern char *optarg;
	extern int opterr, optopt;

	elog_init();
	verbose = 0;
	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":p:n:v");
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
		case 'n':
			numcpus = atoi(optarg);
			break;
		case 'p':
			port = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			assert(0);
		}
	} while (fin == 0);
	if (unlikely(verbose)) {
		elog("Listening on port: %s\n", port);
	}
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_flags = AI_PASSIVE|AI_NUMERICSERV;
	retv = getaddrinfo(NULL, port, &hint, &svrinfo);
	if (retv != 0) {
		elog("getaddrinfo failed: %s\n", gai_strerror(retv));
		return 1;
	}
	sock = socket(svrinfo->ai_family, svrinfo->ai_socktype,
			svrinfo->ai_protocol);
	if (unlikely(sock == -1)) {
		elog("Cannot create socket: %s\n", strerror(errno));
		freeaddrinfo(svrinfo);
		return 1;
	}

	retv = bind(sock, svrinfo->ai_addr, svrinfo->ai_addrlen);
	if (unlikely(retv == -1)) {
		elog("Cannot bind: %s.\n", strerror(errno));
		freeaddrinfo(svrinfo);
		return 2;
	}
	freeaddrinfo(svrinfo);

	if (numcpus == 0) {
		numcpus = cpu_cores();
		if (!cpu_hyper_threading())
			numcpus *= 2;
	}
	elog("Maximum workers: %d\n", numcpus);

	memset(&mact, 0, sizeof(mact));
	mact.sa_handler = sig_handler;
	if (sigaction(SIGINT, &mact, NULL) == -1 ||
			sigaction(SIGTERM, &mact, NULL) == -1)
		elog("Warning: cannot install signal handler: %s\n",
				strerror(errno));
	INIT_LIST_HEAD(&threads);
	buflen = 1024;
	buf = malloc(buflen);
	if (!buf) {
		elog("Out of Memory");
		return 3;
	}

	while (global_exit == 0) {
		peer_addr_len = sizeof(struct sockaddr_storage);
		nread = recvfrom(sock, buf, buflen - 1, 0,
				(struct sockaddr *)&peer_addr, &peer_addr_len);
		if (nread == -1 && errno != EINTR) {
			elog("recvfrom failed: %s\n",
					strerror(errno));
			retv = 5;
			goto exit_30;
		}
		if (nread <= 0)
			continue;
		buf[nread] = 0;
		if (verbose)
			elog("%s\n", buf);

		worker = malloc(sizeof(struct thread_worker));
		if (!worker) {
			elog("Out of Memory.\n");
			retv = 6;
			goto exit_30;
		}
		worker->w_count = &w_count;
		worker->fin = 0;
		retv = lease_parse(buf, &worker->inf);
		if (retv == 0) {
			free(worker);
			continue;
		} else if (retv == -1) {
			free(worker);
			retv = 7;
			goto exit_30;
		}
		list_for_each_entry(wentry, &threads, lst) {
			if (worker_equal(wentry, worker))
				break;
		}
		if (&wentry->lst != &threads) {
			free(worker);
			continue;
		}
		while (w_count >= numcpus) {
			elog("Stalling...\n");
			op_nanosleep(&itv);
			list_for_each_entry_safe(wentry, nxtw, &threads, lst) {
				if (wentry->fin == -1) {
					pthread_join(wentry->thid, NULL);
					list_del(&wentry->lst, &threads);
					free(wentry);
					nworker -= 1;
				}
			}
		}
		
		atomic_inc(&w_count);
		sysret = pthread_create(&worker->thid, NULL, process_echo,
				worker);
		if (sysret) {
			elog("Thread creation failed: %s\n", strerror(sysret));
			atomic_dec(&w_count);
			free(worker);
			continue;
		}
		list_add(&worker->lst, &threads);
		if (verbose)
			dump_worker(worker);
		list_for_each_entry_safe(wentry, nxtw, &threads, lst) {
			if (wentry->fin == -1) {
				pthread_join(wentry->thid, NULL);
				list_del(&wentry->lst, &threads);
				free(wentry);
				nworker -= 1;
			}
		}
	}

exit_30:
	elog("Waiting for all workers to finish...\n");
	fflush(stdout);
	while (nworker > 0) {
		list_for_each_entry_safe(wentry, nxtw, &threads, lst) {
			if (wentry->fin == -1) {
				pthread_join(wentry->thid, NULL);
				list_del(&wentry->lst, &threads);
				free(wentry);
				nworker -= 1;
			}
		}
		nanosleep(&itv, NULL);
	}
	elog("exit...\n");

	free(buf);
	close(sock);
	return retv;
}
