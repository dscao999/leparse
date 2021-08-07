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

struct thread_worker {
	struct lease_info inf;
	pthread_t thid;
	struct list_head lst;
	int fin;
};

static inline int worker_equal(const struct thread_worker *w1,
		const struct thread_worker *w2)
{
	return (w1->inf.tm == w2->inf.tm) &&
			(strcmp(w1->inf.mac, w2->inf.mac) == 0);
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
	if (retv)
		elog("Somethin wrong in lease processing.\n");
	while (tm - me->inf.tm < 2) {
		nanosleep(&itv, NULL);
		tm = time(NULL);
	}
	me->fin = -1;
	return NULL;
}

int main(int argc, char *argv[])
{
	struct sigaction mact;
	struct addrinfo hint, *svrinfo, *adr;
	int retv, sock, eno, buflen, fin, c, leave, verbose;
	int numcpus = 6, sysret;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	ssize_t nread;
	char *buf, *tok, *ip, *start, *mac;
	const char *port = "7800";
	struct lease_info *linfo;
	time_t tm;
	int nworker = 0;
	struct list_head threads;
	struct thread_worker *worker, *wentry, *nxtw;
	static const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};
	extern char *optarg;
	extern int opterr, optopt;

	verbose = 0;
	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":p:v");
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
		case 'v':
			verbose = 1;
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
	numcpus = cpu_cores();
	if (!cpu_hyper_threading())
		numcpus *= 2;
	printf("Maximum workers: %d\n", numcpus);

	memset(&mact, 0, sizeof(mact));
	mact.sa_handler = sig_handler;
	if (sigaction(SIGINT, &mact, NULL) == -1 ||
			sigaction(SIGTERM, &mact, NULL) == -1)
		elog("Warning: cannot install signal handler: %s\n",
				strerror(errno));
	INIT_LIST_HEAD(&threads);
	buflen = 1024;
	buf = malloc(buflen);

	while (global_exit == 0) {
		peer_addr_len = sizeof(struct sockaddr_storage);
		nread = recvfrom(sock, buf, buflen - 1, 0,
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
		if (verbose)
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
		worker = malloc(sizeof(struct thread_worker));
		if (!worker) {
			elog("Out of Memory.\n");
			break;
		}
		linfo = &worker->inf;
		linfo->tm = tm;
		linfo->leave = leave;
		strcpy(linfo->mac, mac);
		strcpy(linfo->ip, ip);
		list_for_each_entry(wentry, &threads, lst) {
			if (worker_equal(wentry, worker))
				break;
		}
		if (&wentry->lst != &threads) {
			free(worker);
			continue;
		}
		while (nworker >= numcpus) {
			printf("Stalling...\n");
			nanosleep(&itv, NULL);
			list_for_each_entry_safe(wentry, nxtw, &threads, lst) {
				if (wentry->fin == -1) {
					pthread_join(wentry->thid, NULL);
					list_del(&wentry->lst, &threads);
					free(wentry);
					nworker -= 1;
				}
			}
		}
		
		worker->fin = 0;
		sysret = pthread_create(&worker->thid, NULL, process_echo,
				worker);
		if (sysret) {
			elog("Thread creation failed: %s\n", strerror(sysret));
			free(worker);
		} else
			list_add(&worker->lst, &threads);
		list_for_each_entry_safe(wentry, nxtw, &threads, lst) {
			if (wentry->fin == -1) {
				pthread_join(wentry->thid, NULL);
				list_del(&wentry->lst, &threads);
				free(wentry);
				nworker -= 1;
			}
		}
	}
	printf("Waiting for all workers to finish...");
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
	printf("exit...\n");

exit_20:
	free(buf);
	close(sock);
	return retv;
}
