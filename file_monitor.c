#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include "file_monitor.h"

static int monitor_add(struct file_watch *fw)
{
	int sysret, count;
	struct stat mstat;
	uint32_t emask;
	static const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};

	if (fw->wd != -1) {
		sysret = inotify_rm_watch(fw->fd, fw->wd);
		if (sysret == -1)
			fprintf(stderr, "Cannot remove old watch fd: %s\n",
					strerror(errno));
		fw->wd = -1;
	}

	do {
		nanosleep(&itv, NULL);
		sysret = stat(fw->lfile, &mstat);
		count += 1;
	} while (sysret == -1 && errno == ENOENT && count < 10);
	if (sysret == -1) {
		fprintf(stderr, "stat failed %s: %s\n", fw->lfile,
				strerror(errno));
		return sysret;
	}
	fw->offset = mstat.st_size;

	emask = IN_MODIFY|IN_MOVE_SELF;
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
	fw->offset = 0;
	fw->mod_action = NULL;

	retv = monitor_add(fw);

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
	int len, i, moved, retv;
	struct inotify_event *ev;

	len = read(fw->fd, fw->evbuf, sizeof(fw->evbuf));
	if (len < 0) {
		fprintf(stderr, "Watch read failed: %s\n", strerror(errno));
		return len;
	}
	i = 0;
	moved = 0;
	while (i < len && moved == 0) {
		ev = (struct inotify_event *)(fw->evbuf + i);
		if (ev->mask & IN_MOVE_SELF) {
			retv = monitor_add(fw);
			if (retv < 0)
				fprintf(stderr, "Cannot add monitor after " \
					       "file was moved.\n");
			moved = 1;
		} else if (ev->mask & IN_MODIFY) {
			if (fw->mod_action == NULL)
				printf("File %s modified.\n", fw->lfile);
			else
				fw->offset = fw->mod_action(fw);
		}
		i += sizeof(struct inotify_event) + ev->len;
		if (moved == 1 && i < len)
			fprintf(stderr, "Events after file was moved.\n");
	}
	return len;
}
