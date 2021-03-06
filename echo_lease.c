#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <pwd.h>
#include "miscs.h"
#include "list_head.h"
#include "cpuinfo.h"
#include "pipe_execution.h"
#include "dbproc.h"

int verbose = 0;

#define SEMSPER	256
#define NUMSEMS	(SEMSPER*2)

struct post_data {
	int semset;
};
static struct post_data g_data = {.semset = -1};

static void post_processing(int retv, void *arg)
{
	struct post_data *data = (struct post_data *)arg;
	if (data->semset != -1) {
		semctl(data->semset, IPC_RMID, 0);
		data->semset = -1;
	}
}

struct thread_worker {
	struct lease_info inf;
	pthread_t thid;
	struct list_head lst;
	volatile int *w_count;
	const char *user_name;
	void *id;
	int fin;
};

static inline int worker_equal(const struct thread_worker *w1,
		const struct thread_worker *w2)
{
	return (w1->inf.tm == w2->inf.tm) &&
			(strcmp(w1->inf.mac, w2->inf.mac) == 0) &&
			 (w1->inf.leave == w2->inf.leave);
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

	retv = dbproc(&me->inf, me->user_name);
	atomic_dec(me->w_count);
	if (retv)
		elog("Somethin wrong in lease processing.\n");
	tm = time(NULL);
	while (tm - me->inf.tm < 4) {
		op_nanosleep(&itv);
		tm = time(NULL);
	}
	me->fin = -1;
	return NULL;
}

static int lease_parse(const char *info, struct lease_info *linfo)
{
	char *buf, *tok, *saveptr;
	int retv = 0, len;
	static const char *token = " ;{}";

	len = strlen(info);
	buf = malloc(len+1);
	if (!buf) {
		elog("Out of Memory");
		return -1;
	}
	strcpy(buf, info);
	tok = strtok_r(buf, token, &saveptr);
	memset(linfo, 0, sizeof(struct lease_info));
	while (tok) {
		if (strcmp(tok, "leave") == 0) {
			linfo->leave = 1;
			tok = strtok_r(NULL, token, &saveptr);
			strcpy(linfo->ip, tok);
		} else if (strcmp(tok, "lease") == 0) {
			linfo->leave = 0;
			tok = strtok_r(NULL, token, &saveptr);
			strcpy(linfo->ip, tok);
		} else if (strcmp(tok, "start") == 0) {
			tok = strtok_r(NULL, token, &saveptr);
			linfo->tm = atoll(tok);
		} else if (strcmp(tok, "hardware") == 0) {
			tok = strtok_r(NULL, token, &saveptr);
			if (strcmp(tok, "ethernet") == 0) {
				tok = strtok_r(NULL, token, &saveptr);
				strcpy(linfo->mac, tok);
			}
		} else if (strcmp(tok, "hostid") == 0) {
			tok = strtok_r(NULL, token, &saveptr);
			linfo->hostid = atoll(tok);
		}
		tok = strtok_r(NULL, token, &saveptr);
	}
	if (likely((strlen(linfo->ip) != 0 && strlen(linfo->mac) != 0 &&
			linfo->hostid != 0 && linfo->tm != 0)))
		retv = 1;
	free(buf);
	return retv;
}

int main(int argc, char *argv[])
{
	struct sigaction mact;
	struct addrinfo hint, *svrinfo;
	int retv, sock, buflen, fin, c;
	int numcpus = 0, sysret, len;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	ssize_t nread;
	char *buf, user_name[24];
	const char *port = "7800";
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
	on_exit(post_processing, &g_data);
	if (verbose) {
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
/*	numcpus = 1; */
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
	if (unlikely(!buf)) {
		elog("Fatal Error! Out of Memory in %s\n", __func__);
		return 3;
	}

	struct passwd *pwd;
	struct stat *mst;
	int genkey = 0;
	mst = (struct stat *)(buf + 1024 - sizeof(struct stat));
	pwd = getpwuid(getuid());
	if (unlikely(!pwd)) {
		elog("Fatal Error! getpwuid failed: %s\n", strerror(errno));
		retv = 4;
		goto exit_10;
	}
	strcpy(user_name, pwd->pw_name);
	strcpy(buf, pwd->pw_dir);
	strcat(buf, "/.ssh/id_ecdsa");
	if (stat(buf, mst) != 0) 
		genkey = 1;
	strcpy(buf, pwd->pw_dir);
	strcat(buf, "/.ssh/id_ecdsa.pub");
	if (stat(buf, mst) != 0)
		genkey = 1;
	if (genkey) {
		strcpy(buf, pwd->pw_dir);
		strcat(buf, "/.ssh/id_ecdsa");
		unlink(buf);
		strcpy(buf, pwd->pw_dir);
		strcat(buf, "/.ssh/id_ecdsa.pub");
		unlink(buf);
		len = sprintf(buf, "ssh-keygen -t ecdsa -N \"\" " \
				"-f %s/.ssh/id_ecdsa", pwd->pw_dir); 
		retv = one_execute(buf+len, buflen-len, buf, NULL);
		if (verbose)
			elog("%s\n", buf+len);
		if (retv) {
			elog("Fatal Error! Cannot generate ssh key\n");
			goto exit_10;
		}
	}
	if (delete_null_uuid(user_name) < 0)
		goto exit_10;

	g_data.semset = semget(IPC_PRIVATE, NUMSEMS, IPC_CREAT|IPC_EXCL|0600);
	if (unlikely(g_data.semset == -1)) {
		elog("Cannot get a semphore set: %s\n", strerror(errno));
		goto exit_10;
	}

	union semun {
		int val;
		struct semid_ds *buf;
		unsigned short *array;
		struct seminfo *__buf;
	} smset;
	unsigned short *cval;
	int i;
	smset.array = malloc(NUMSEMS*sizeof(unsigned short));
	for (cval = smset.array, i = 0; i < NUMSEMS; i++,cval++)
		*cval = 1;
	retv = semctl(g_data.semset, 0, SETALL,  smset);
	if (unlikely(retv == -1)) {
		elog("Cannot set initial semphore: %s\n", strerror(errno));
		goto exit_20;
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
		worker->user_name = user_name;
		worker->id = worker;
		sysret = lease_parse(buf, &worker->inf);
		if (sysret == 0) {
			free(worker);
			elog("'%s' ignored\n", buf);
			continue;
		} else if (sysret == -1) {
			free(worker);
			retv = 7;
			goto exit_30;
		}
		worker->inf.semset = g_data.semset;
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
		list_for_each_entry_safe(wentry, nxtw, &threads, lst) {
			if (wentry->fin == -1) {
				pthread_join(wentry->thid, NULL);
				list_del(&wentry->lst, &threads);
				free(wentry);
			}
		}
	}

exit_30:
	elog("Waiting for all workers to finish...\n");
	do
		list_for_each_entry_safe(wentry, nxtw, &threads, lst) {
			if (wentry->fin == -1) {
				pthread_join(wentry->thid, NULL);
				list_del(&wentry->lst, &threads);
				free(wentry);
			}
		}
	while (!list_empty(&threads));
	elog("exit...\n");

exit_20:
	semctl(g_data.semset, IPC_RMID, 0);
	g_data.semset = -1;
exit_10:
	free(buf);
	close(sock);
	return retv;
}
