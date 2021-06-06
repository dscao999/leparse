#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <assert.h>
#include "file_monitor.h"

static int monitor_add(struct file_watch *fw, uint32_t mask)
{
	int sysret, count;
	struct stat mstat;
	uint32_t emask;
	static const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};
	time_t curtm;

	if (fw->wd != -1) {
		sysret = inotify_rm_watch(fw->fd, fw->wd);
		if (sysret == -1 && (mask & IN_DELETE_SELF) == 0)
			fprintf(stderr, "Cannot remove old watch fd %d: %s\n",
					fw->wd, strerror(errno));
		fw->wd = -1;
	}

	count = 0;
	do {
		curtm = time(NULL);
		printf("Waiting for file: %s at %s", fw->lfile,
				asctime(localtime(&curtm)));
		nanosleep(&itv, NULL);
		sysret = stat(fw->lfile, &mstat);
		count += 1;
	} while (sysret == -1 && errno == ENOENT && count < 60);
	if (sysret == -1) {
		fprintf(stderr, "stat failed %s: %s\n", fw->lfile,
				strerror(errno));
		exit(12);
	}
	if (mask & (IN_DELETE_SELF|IN_MOVE_SELF))
		fw->offset = 0;
	else
		fw->offset = mstat.st_size;

	emask = IN_MODIFY|IN_MOVE_SELF|IN_DELETE_SELF;
	sysret = inotify_add_watch(fw->fd, fw->lfile, emask);
	if (sysret == -1)
		fprintf(stderr, "Cannot add watch to %s: %s\n",
				fw->lfile, strerror(errno));
	fw->wd = sysret;
	return sysret;
}

int monitor_init(const char *fname, struct file_watch *fw)
{
	int retv = 0;
	char *dirname, *lslash;

	fw->offset = 0;
	fw->mod_action = NULL;
	fw->wd = -1;
	fw->fd = inotify_init();
	if (fw->fd == -1) {
		fprintf(stderr, "inotify init failed: %s\n", strerror(errno));
		return fw->fd;
	}
	if (realpath(fname, fw->lfile) == NULL) {
		fprintf(stderr, "Cannot resolve file %s: %s\n", fname, strerror(errno));
		close(fw->fd);
		return -errno;
	}
	dirname = malloc(strlen(fw->lfile)+1);
	strcpy(dirname, fw->lfile);
	lslash = strrchr(dirname, '/');
	assert(lslash != NULL);
	*lslash = 0;
	printf("Watch dir: %s\n", dirname);
	fw->wdir = inotify_add_watch(fw->fd, dirname,
			IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO);
	if (fw->wdir == -1) {
		fprintf(stderr, "Cannot watch %s: %s\n",
				dirname, strerror(errno));
		free(dirname);
		return fw->wdir;
	}
	fw->create_new = 0;
	free(dirname);

	retv = monitor_add(fw, 0);
	return retv;
}

void monitor_exit(struct file_watch *fw)
{
	if (fw->wd != -1)
		inotify_rm_watch(fw->fd, fw->wd);
	close(fw->fd);
	fw->fd = -1;
	fw->wd = -1;
}

int monitor_watch(struct file_watch *fw)
{
	int len, i, retv, sysret, numevt, llen;
	struct inotify_event *ev;
	time_t curtm;
	struct pollfd mfd;
	static const char *lease_name = "dhcpd.leases.";

	llen = strlen(lease_name);
	mfd.fd = fw->fd;
	mfd.events = POLLIN;
	mfd.revents = 0;
	sysret = poll(&mfd, 1, 250);
	if (sysret == -1) {
		if (errno != EINTR)
			fprintf(stderr, "poll failed: %s\n", strerror(errno));
		else
			sysret = 0;
		return sysret;
	} else if (sysret == 0)
		return sysret;
	if (mfd.revents & (POLLHUP|POLLERR|POLLNVAL))
		return -1;

	len = read(fw->fd, fw->evbuf, sizeof(fw->evbuf));
	if (len < 0) {
		fprintf(stderr, "Watch read failed: %s\n", strerror(errno));
		return len;
	}
	i = 0;
	numevt = 0;
	while (i < len) {
		ev = (struct inotify_event *)(fw->evbuf + i);
		if (ev->mask & (IN_MOVE_SELF|IN_DELETE_SELF)) {
			curtm = time(NULL);
			printf("Lease File %s moved/deleted at %s", ev->name,
					asctime(localtime(&curtm)));
			/*retv = monitor_add(fw, ev->mask);
			if (retv < 0) {
				fprintf(stderr, "Cannot add monitor after " \
					       "file was moved/deleted.\n");
				exit(10);
			}*/
		} else if (ev->mask & IN_CREATE) {
			assert(fw->wdir == ev->wd);
			if (memcmp(ev->name, lease_name, llen) != 0)
				goto next_item;
			strcpy(fw->tmpfile, ev->name);
			fw->create_new = 1;
			curtm = time(NULL);
			printf("File %s created at %s", ev->name,
					asctime(localtime(&curtm)));
		} else if (ev->mask & IN_MOVED_FROM) {
			assert(fw->wdir == ev->wd);
			if (memcmp(ev->name, lease_name, llen) != 0 ||
					fw->create_new == 0)
				goto next_item;
			fw->create_new = 0;
			curtm = time(NULL);
			printf("File %s get moved at %s", ev->name,
					asctime(localtime(&curtm)));
			retv = monitor_add(fw, ev->mask);
			if (retv < 0) {
				fprintf(stderr, "Cannot add monitor after " \
						"file was moved.\n");
				exit(10);
			}
		} else if (ev->mask & IN_MODIFY) {
			if (fw->mod_action == NULL) {
				curtm = time(NULL);
				printf("File %s modified at %s", fw->lfile,
						asctime(localtime(&curtm)));
			} else
				fw->offset = fw->mod_action(fw, fw->mon_data);
		}
next_item:
		i += sizeof(struct inotify_event) + ev->len;
		numevt += 1;
	}
	return len;
}
