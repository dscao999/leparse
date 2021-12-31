#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <net/if.h>
#include <sys/random.h>

static volatile int global_exit = 0;
int verbose = 0;

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

static void sockaddr_parse(const struct sockaddr *addr)
{
	const struct sockaddr_in *sockin;
	char ip[16];

	sockin = (const struct sockaddr_in *)addr;
	printf("sin family: %hd, port: %hd\n", ntohs(sockin->sin_family),
			ntohs(sockin->sin_port));
	printf("IP: %s\n", inet_ntop(AF_INET, &sockin->sin_addr, ip, sizeof(ip)));
	fflush(stdout);
}

static const char *netdir = "/sys/class/net";

struct idinfo {
	unsigned long tmstp;
	char iface[16];
	char ip[24];
	char mac[24];
	struct idinfo *nxt;
};

struct idinfo * getinfo(void)
{
	struct idinfo *inf, *inf1st, *inf_prev;
	DIR *dir;
	struct dirent *dent;
	int numb, sockd;
	char *macfile, *lnknam, *buf;
	FILE *fin;
	char *ln, *mac, *iface, *ip;
	struct ifreq *mreq;
	struct sockaddr_in *ipv4_addr;
	time_t tmstp;

	mreq = malloc(sizeof(struct ifreq)+1152);
	if (!mreq) {
		fprintf(stderr, "Out of Memory!\n");
		exit(100);
	}
	tmstp = time(NULL);
	macfile = (char *)(mreq + 1);
	lnknam = macfile + 256;
	buf = lnknam + 256;
	iface = buf + 256;
	mac = iface + 128;
	ip = mac + 128;

	sockd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockd == -1) {
		fprintf(stderr, "Cannot create socket: %s\n", strerror(errno));
		return NULL;
	}
	inf1st = NULL;
	inf_prev = NULL;
	dir = opendir(netdir);
	do {
		errno = 0;
		dent = readdir(dir);
		if (dent == NULL) {
			if (errno == 0)
				break;
			fprintf(stderr, "NIC name read failed: %s\n",
					strerror(errno));
			break;
		}
		if ((dent->d_type & DT_LNK) == 0)
			continue;
		strcpy(iface, dent->d_name);
		strcpy(macfile, netdir);
		strcat(macfile, "/");
		strcat(macfile, iface);
		numb = readlink(macfile, lnknam, 256);
		if (numb == -1) {
			fprintf(stderr, "readlink failed for %s: %s\n",
					macfile, strerror(errno));
			continue;
		}
		lnknam[numb] = 0;
		if (strstr(lnknam, "/usb") || strstr(lnknam, "/virtual"))
			continue;
		strcpy(mreq->ifr_name, iface);
		numb = ioctl(sockd, SIOCGIFADDR, mreq);
		if (numb == -1) {
			fprintf(stderr, "Cannot get IP address of %s: %s\n",
					iface, strerror(errno));
			continue;
		}
		ipv4_addr = (struct sockaddr_in *)&mreq->ifr_addr;
		if (!inet_ntop(AF_INET, &ipv4_addr->sin_addr, ip, 128))
			continue;

		strcat(macfile, "/address");
		fin = fopen(macfile, "rb");
		if (!fin) {
			fprintf(stderr, "Cannot open %s for read: %s\n",
					macfile, strerror(errno));
			continue;
		}
		numb = fread(mac, 1, 128, fin);
		if (numb <= 0) {
			fprintf(stderr, "Cannot read %s: %s\n", macfile,
					strerror(errno));
			fclose(fin);
			continue;
		}
		fclose(fin);
		mac[numb] = 0;
		ln = strchr(mac, '\n');
		if (ln)
			*ln = 0;
		inf = malloc(sizeof(struct idinfo));
		if (!inf) {
			fprintf(stderr, "Out of Memory.\n");
			exit(100);
		}
		if (inf1st == NULL)
			inf1st = inf;
		if (inf_prev)
			inf_prev->nxt = inf;
		inf->nxt = NULL;
		inf->tmstp = tmstp;
		strcpy(inf->iface, iface);
		strcpy(inf->mac, mac);
		strcpy(inf->ip, ip);
		inf_prev = inf;
	} while (1);
	closedir(dir);
	close(sockd);
	free(mreq);
	return inf1st;
}

static void ping_lidm(struct leserv *serv, const struct idinfo *inf, char *buf,
		int leave, unsigned long hostid)
{
	struct timespec itm, rtm;
	unsigned long rndsec;
	const struct idinfo *curinf;
	int len, sysret;
	static const char *const lease = "lease";
	static const char *const shutdown = "leave";
	static const char *inffmt = "%s %s { start %lu; hardware ethernet %s; "\
				     "hostid %lu}";
	const char *verb;

	verb = lease;
	if (leave)
		verb = shutdown;
	getrandom(&rndsec, sizeof(rndsec), 0);
	itm.tv_sec = 0;
	itm.tv_nsec = rndsec % 1000000000ul;
	for (curinf = inf; curinf; curinf = curinf->nxt) {
		len = sprintf(buf, inffmt, verb, curinf->ip, curinf->tmstp,
				curinf->mac, hostid);
		sysret = sendto(serv->sock, buf, len, 0, &serv->addr,
				serv->addr_len);
		if (sysret == -1) {
			sockaddr_parse(&serv->addr);
			fprintf(stderr, "sendto failed: %s\n", strerror(errno));
			fprintf(stderr, "%d, len: %d, '%s'\n", serv->sock, len, buf);
		}
		if (verbose)
			printf("%s\n", buf);
	}
	do {
		sysret = nanosleep(&itm, &rtm);
		if (sysret == -1) {
			if (errno != EINTR) {
				fprintf(stderr, "nanosleep failed: %s\n", strerror(errno));
				break;
			}
			itm = rtm;
		}
	} while (sysret == -1);
	for (curinf = inf; curinf; curinf = curinf->nxt) {
		len = sprintf(buf, inffmt, verb, curinf->ip, curinf->tmstp,
				curinf->mac, hostid);
		sysret = sendto(serv->sock, buf, len, 0, &serv->addr,
				serv->addr_len);
		if (sysret == -1) {
			sockaddr_parse(&serv->addr);
			fprintf(stderr, "sendto failed: %s\n", strerror(errno));
			fprintf(stderr, "%d, len: %d, '%s'\n", serv->sock, len, buf);
		}
		if (verbose)
			printf("%s\n", buf);
	}
}

int main(int argc, char *argv[])
{
	int fin, c, retv, leave;
	extern char *optarg;
	extern int optind, opterr, optopt;
	struct sigaction mact;
	struct leserv serv;
	struct addrinfo hint, *serv_adr;
	unsigned long hostid;
	static const char * const port_default = "7800";
	static const char * const lidm_default = "localhost";
	const char *lidm, *port;
	struct idinfo *inf, *curinf, *nxt;
	char *buf;

	leave = 0;
	verbose = 0;
	port = NULL;
	lidm = NULL;
	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":s:p:dv");
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
		case 's':
			lidm = strtok(optarg, " ");
			break;
		case 'p':
			port = strtok(optarg, " ");
			break;
		case 'd':
			leave = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			assert(0);
		}
	} while (fin == 0);
	if (!lidm)
		lidm = lidm_default;
	if (!port)
		port = port_default;
	if (verbose) {
		int i;
		for (i = 0; i < argc - 1; i++)
			printf("%s ", argv[i]);
		printf("%s\n", argv[i]);
	}

	memset(&mact, 0, sizeof(struct sigaction));
	mact.sa_handler = sig_handler;
	if (sigaction(SIGINT, &mact, NULL) == -1 ||
			sigaction(SIGTERM, &mact, NULL) == -1)
		fprintf(stderr, "Warning: Signal Handler Installation failed:" \
				" %s\n", strerror(errno));

	memset(&serv, 0, sizeof(serv));
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_flags = AI_NUMERICSERV;
	retv = getaddrinfo(lidm, port, &hint, &serv_adr);
	if (retv != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(retv));
		fprintf(stderr, "lidm: '%s', len: %lu, port: '%s', len: %lu\n",
				lidm, strlen(lidm), port, strlen(port));
		retv = 2;
		return retv;
	}
	serv.addr_len = serv_adr->ai_addrlen;
	memcpy(&serv.addr, serv_adr->ai_addr, serv_adr->ai_addrlen);
	freeaddrinfo(serv_adr);

	serv.sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (serv.sock == -1) {
		fprintf(stderr, "Cannot create socket: %s\n", strerror(errno));
		retv = 3;
		return retv;
	}

	inf = getinfo();
	if (!inf) {
		retv = 3;
		goto exit_10;
	}
	buf = malloc(512);
	if (!buf) {
		fprintf(stderr, "Out of Memory.\n");
		retv = 100;
		goto exit_10;
	}

	hostid = gethostid();
	ping_lidm(&serv, inf, buf, leave, hostid);

	free(buf);
	for (curinf = inf; curinf; curinf = nxt) {
		nxt = curinf->nxt;
		free(curinf);
	}
exit_10:
	close(serv.sock);
	return retv;
}
