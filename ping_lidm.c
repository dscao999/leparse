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

static const char *netdir = "/sys/class/net";

struct idinfo {
	time_t tmstp;
	char iface[16];
	char ip[24];
	char mac[24];
};

const struct idinfo * getinfo(int sockd)
{
	static struct idinfo inf;
	DIR *dir;
	struct dirent *dent;
	int found = 0, numb;
	char macfile[128];
	FILE *fin;
	char *ln;
	struct ifreq *mreq;
	struct sockaddr_in *ipv4_addr;

	mreq = malloc(sizeof(struct ifreq));
	if (!mreq) {
		fprintf(stderr, "Out of Memory!\n");
		exit(100);
	}
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
		if ((dent->d_type & DT_LNK) == 0 ||
				strcmp(dent->d_name, "lo") == 0)
			continue;
		strncpy(inf.iface, dent->d_name, sizeof(inf.iface));
		strcpy(macfile, netdir);
		strcat(macfile, "/");
		strcat(macfile, inf.iface);
		strcat(macfile, "/address");
		fin = fopen(macfile, "rb");
		if (!fin) {
			fprintf(stderr, "Cannot open %s for read: %s\n",
					macfile, strerror(errno));
			continue;
		}
		numb = fread(inf.mac, 1, sizeof(inf.mac), fin);
		if (numb <= 0) {
			fprintf(stderr, "Cannot read %s: %s\n", macfile,
					strerror(errno));
			fclose(fin);
			continue;
		}
		fclose(fin);
		inf.mac[numb] = 0;
		ln = strchr(inf.mac, '\n');
		if (ln)
			*ln = 0;
		strcpy(mreq->ifr_name, inf.iface);
		numb = ioctl(sockd, SIOCGIFADDR, mreq);
		if (numb == -1) {
			fprintf(stderr, "Cannot get IP address of %s: %s\n",
					inf.iface, strerror(errno));
			continue;
		}
		ipv4_addr = (struct sockaddr_in *)&mreq->ifr_addr;
		inet_ntop(AF_INET, &ipv4_addr->sin_addr, inf.ip, sizeof(inf.ip));
		found = 1;
		break;
	} while (1);
	closedir(dir);
	free(mreq);
	if (!found)
		return NULL;
	inf.tmstp = time(NULL);
	return &inf;
}

int main(int argc, char *argv[])
{
	int fin, c, retv;
	extern char *optarg;
	extern int optind, opterr, optopt;
	struct sigaction mact;
	struct leserv serv;
	struct addrinfo hint, *serv_adr;
	static const char *lidm = "127.0.0.1";
	static const char *port = "7800";
	const struct idinfo *inf;

	opterr = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":s:p:");
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
			lidm = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		default:
			assert(0);
		}
	} while (fin == 0);

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

	inf = getinfo(serv.sock);
	if (inf)
		printf("IFACE: %s, IP: %s, MAC: %s\n", inf->iface, inf->ip, inf->mac);

	close(serv.sock);
	return retv;
}
