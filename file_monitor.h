#ifndef FILE_WATCH_DSCAO__
#define FILE_WATCH_DSCAO__
#include <limits.h>
#include <sys/inotify.h>

struct file_watch {
	off_t (*mod_action)(const struct file_watch *fw);
	off_t offset;
	int fd;
	int wd;
	char lfile[256];
	char evbuf[(sizeof(struct inotify_event)+NAME_MAX)*100];
};

int monitor_init(const char *fname, struct file_watch *fw);
void monitor_exit(struct file_watch *fw);
int monitor_watch(struct file_watch *fw);

static inline void monitor_set_action(struct file_watch *fw,
		off_t (*mod_action)(const struct file_watch *fw))
{
	fw->mod_action = mod_action;
}

#endif /* FILE_WATCH_DSCAO__ */
