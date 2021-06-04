#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/inotify.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static volatile int global_exit = 0;

void sig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT)
		global_exit = 1;
}

int main(int argc, char *argv[])
{
	const char *dir = "/var/lib/dhcp";
	int fd, wd, ebuf_len, retv = 0;
	int len, i;
	struct sigaction mact;
	char *ebuf;
	struct inotify_event *ev;

	ebuf_len = 128;
	ebuf = malloc(ebuf_len);

	memset(&mact, 0, sizeof(mact));
	mact.sa_handler = sig_handler;
	if (sigaction(SIGTERM, &mact, NULL) == -1 ||
			sigaction(SIGINT, &mact, NULL) == -1)
		fprintf(stderr, "Warning: Cannot install signal handler: %s\n",
				strerror(errno));

	fd = inotify_init();
	if (fd == -1) {
		fprintf(stderr, "Cannot initialize inotify: %s\n", strerror(errno));
		return 1;
	}
	wd = inotify_add_watch(fd, dir, IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO);
	if (wd == -1) {
		fprintf(stderr, "Cannot add watch for %s: %s\n", dir, strerror(errno));
		close(wd);
		return 2;
	}
	do {
		len = read(fd, ebuf, ebuf_len);
		if (len == -1) {
		       	if (errno == EINTR)
				continue;
			fprintf(stderr, "Events read failed: %s\n", strerror(errno));
			retv = 3;
			break;
		} else if (len == 0)
			continue;
		i = 0;
		while (i < len) {
			ev = (struct inotify_event *)(ebuf + i);
			if (ev->mask & IN_CREATE)
				printf("File %s created.\n", ev->name);
			if (ev->mask & IN_DELETE)
				printf("File %s deleted.\n", ev->name);
			if (ev->mask & IN_MOVED_FROM)
				printf("File %s was moved from.\n", ev->name);
			if (ev->mask & IN_MOVED_TO)
				printf("File %s was moved to.\n", ev->name);
			i += sizeof(struct inotify_event) + len;
		}
	} while (global_exit == 0);

	close(fd);
	free(ebuf);
	return retv;
}
