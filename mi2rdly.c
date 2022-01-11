#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include "miscs.h"
#include "pipe_execution.h"

#define RESLEN	2048
#define PATHLEN	256
#define CMDLEN 1024
#define KVERLEN 64

static volatile int global_exit = 0;

static void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

static const
char micmds[] =	"# check if stateless is present\n" \
		"for x in $(cat /proc/cmdline); do\n" \
		"\tif [ \"$x\" = \"stateless\" ]; then\n" \
		"\t\tcachedev=$(blkid|fgrep \"LIOS_CACHE\"|cut -d: -f1)\n" \
		"\t\t[ -b \"$cachedev\" ] || break\n" \
		"\t\t[ \"$quiet\" != \"y\" ] && log_begin_msg \"Building " \
		"Overlay RootFS\"\n" \
		"\t\tupd=root_upper\n\t\tlwd=root_lower\n" \
		"\t\tmkdir /$upd /$lwd\n" \
		"\t\tmkfs.xfs -L LIOS_CACHE -f $cachedev\n" \
		"\t\tmount $cachedev /$upd\n" \
		"\t\tmkdir /$upd/proc /$upd/dev /$upd/sys /$upd/run " \
		"/$upd/work /$upd/root\n" \
		"\t\tmount --move ${rootmnt} /$lwd\n" \
		"\t\tmount -o remount -o ro /$lwd\n" \
		"\t\tmount -t overlay -o lowerdir=/$lwd,upperdir=/$upd/root," \
		"workdir=/$upd/work root_overlay ${rootmnt}\n" \
		"\t\t[ \"$quiet\" != \"y\" ] && log_begin_msg " \
		"\"Finish Building Overlay RootFS\"\n" \
		"\t\tbreak\n\tfi\ndone\n";

int main(int argc, char *argv[])
{
	uid_t me;
	char *res, *kver, *tokchr, *cwd, *initramfs, *cmdbuf, *tmpramfs;
	char *mkfs0, *mkfs1, *troot, *splash, *tmpgrub, *tmpinit, *scratch;
	int retv = 0, found, numbr, sysret, skgrub, mpid;
	unsigned long buflen;
	int numbw, olen;
	FILE *fin, *fout;
	struct stat mst;

	elog_init();
	me = getuid();
	if (me != 0) {
		elog("root priviledge required\n");
		return 1;
	}
	buflen = RESLEN + KVERLEN + 7*PATHLEN + CMDLEN;
	cwd = malloc(buflen);
	if (unlikely(!cwd)) {
		elog("Out of Memory\n");
		return ENOMEM;
	}
	troot = cwd + PATHLEN;
	initramfs = troot + PATHLEN;
	tmpgrub = initramfs + PATHLEN;
	tmpinit = tmpgrub + PATHLEN;
	tmpramfs = tmpinit + PATHLEN;
	scratch = tmpramfs + PATHLEN;
	res = scratch + PATHLEN;
	kver = res + RESLEN;
	cmdbuf = kver + KVERLEN;
	buflen = RESLEN + KVERLEN + CMDLEN;
	if (unlikely(!getcwd(cwd, PATHLEN))) {
		elog("Cannot get current directory: %s\n", strerror(errno));
		retv = errno;
		goto exit_10;
	}
	retv = pipe_execute(res, RESLEN, "findfs LABEL=LIOS_CACHE", NULL, NULL);
	if (unlikely(retv)) {
		elog("Cannot find LIOS_CACHE partition in the system: %s\n",
				res);
		retv = 2;
		goto exit_10;
	} else
		printf("Cache Partition: %s\n", res);

	fin = fopen("/proc/mounts", "rb");
	if (unlikely(!fin)) {
		elog("Cannot open /proc/mounts: %s\n", strerror(errno));
		goto exit_10;
	}
	do {
		numbr = getline(&res, &buflen, fin);
		if (strstr(res, "root_overlay / overlay")) {
			elog("Current OS is already readonly\n");
			fclose(fin);
			goto exit_10;
		}
	} while (!feof(fin) && !ferror(fin));
	if (unlikely(ferror(fin))) {
		elog("/proc/mounts read failed: %s\n", strerror(errno));
		retv = errno;
	}
	fclose(fin);
	if (retv)
		goto exit_10;
	fin = fopen("/proc/cmdline", "rb");
	if (unlikely(!fin)) {
		elog("Cannot open file /proc/cmdline for reading: %s\n",
				strerror(errno));
		retv = errno;
		goto exit_10;
	}

	numbr = fread(res, 1, RESLEN-1, fin);
	if (unlikely(numbr == -1)) {
		elog("Cannot read file /proc/cmdline: %s\n", strerror(errno));
		retv = errno;
		fclose(fin);
		goto exit_10;
	}
	res[numbr] = 0;
	fclose(fin);
	found = 0;
	tokchr = strtok(res, " ");
	while (tokchr) {
		if (strncmp(tokchr, "BOOT_IMAGE=", 11) == 0) {
			found = 1;
			break;
		}
		tokchr = strtok(NULL, " ");
	}
	if (unlikely(!found)) {
		elog("Cannot figure out current kernel version\n");
		retv = 3;
		goto exit_10;
	}
	strcpy(kver, strchr(tokchr, '-'));
	mpid = getpid();

	struct sigaction mact;
	memset(&mact, 0, sizeof(mact));
	mact.sa_handler = sig_handler;
	if (sigaction(SIGINT, &mact, NULL) == -1 ||
			sigaction(SIGTERM, &mact, NULL) == -1)
		elog("Cannot install handler for INT and TERM\n");

	sprintf(tmpinit, "/tmp/init-%d", mpid);
	sprintf(tmpgrub, "/tmp/grub-%d.cfg", mpid);
	sprintf(tmpramfs, "/tmp/initramfs-%d.img", mpid);
	sprintf(troot, "troot-%d", mpid);
	sysret = mkdir(troot, 0755);
	if (unlikely(sysret == -1)) {
		elog("Cannot mkdir %s: %s\n", res, strerror(errno));
		retv = errno;
		goto exit_10;
	}
	sprintf(initramfs, "/boot/initrd.img%s", kver);
	fin = fopen(initramfs, "rb");
	if (!fin) {
		elog("Cannot open %s for reading: %s\n", initramfs,
				strerror(errno));
		retv = errno;
		goto exit_10;
	}
	fclose(fin);
	if (unlikely(chdir(troot) == -1)) {
		elog("Cannot change into %s: %s\n", res, strerror(errno));
		retv = errno;
		goto exit_10;
	}
	if (global_exit)
		goto exit_10;
	sprintf(cmdbuf, "gunzip -c %s|cpio -id", initramfs);
	printf("Expanding %s ...\n", initramfs);
	retv = pipe_execute(res, RESLEN, cmdbuf, NULL, NULL);
	if (unlikely(retv)) {
		elog("%s failed: %s\n", cmdbuf, res);
		goto exit_20;
	}
	if (unlikely(global_exit))
		goto exit_20;
	
	mkfs0 = "/usr/share/lentools/mkfs.xfs";
	mkfs1 = "usr/sbin/mkfs.xfs";
	sysret = stat(mkfs1, &mst);
	if (sysret == 0) {
		printf("Initramfs already supports stateless OS\n");
		goto exit_20;
	}
	fin = fopen(mkfs0, "rb");
	if (unlikely(!fin)) {
		elog("Failed to open %s: %s\n", mkfs0, strerror(errno));
		goto exit_20;
	}
	fout = fopen(mkfs1, "wb");
	if (unlikely(!fout)) {
		elog("Faled to open %s: %s\n", mkfs1, strerror(errno));
		fclose(fin);
		goto exit_20;
	}
	do {
		numbr = fread(res, 1, RESLEN, fin);
		if (numbr > 0) {
			numbw = fwrite(res, 1, numbr, fout);
			assert(numbr == numbw);
		}
	} while (!feof(fin) && !ferror(fin) && !ferror(fout));
	if (unlikely(ferror(fin))) {
		elog("Failed to read %s: %s\n", mkfs0, strerror(errno));
		retv = errno;
	}
	if (unlikely(ferror(fout))) {
		elog("Failed to write %s: %s\n", mkfs1, strerror(errno));
		retv = errno;
	}
	fclose(fout);
	fclose(fin);
	if (unlikely(retv||global_exit))
		goto exit_20;
	if (unlikely(chmod(mkfs1, 0755) == -1)) {
		elog("Cannot chmod %s: %s\n", mkfs1, strerror(errno));
		goto exit_20;
	}

	fin = fopen("init", "rb");
	fout = fopen(tmpinit, "wb");
	do {
		numbr = getline(&res, &buflen, fin);
		numbw = fwrite(res, 1, numbr, fout);
		assert(numbr == numbw);
		if (strcmp(res, "maybe_break bottom\n") == 0)
			break;
	} while (!feof(fin) && !ferror(fin) && !ferror(fout));
	if (unlikely(feof(fin))) {
		elog("Premature end of file: init\n");
		retv = 11;
	}
	if (unlikely(ferror(fin)||ferror(fout))) {
		elog("Read/Write init script failed: %s\n", strerror(errno));
		retv = errno;
	}
	if (unlikely(retv||global_exit)) {
		fclose(fin);
		fclose(fout);
		goto exit_20;
	}
	olen = getline(&res, &buflen, fin);
	if (strcmp(res, "# check if stateless is present\n") == 0) {
		elog("init script already supports stateless boot\n");
		fclose(fin);
		fclose(fout);
		goto exit_20;
	}

	numbr = strlen(micmds);
	numbw = fwrite(micmds, 1, numbr, fout);
	assert(numbr == numbw);
	numbr = olen;
	do {
		if (numbr > 0) {
			numbw = fwrite(res, 1, numbr, fout);
			assert(numbr == numbw);
		}
		numbr = getline(&res, &buflen, fin);
	} while (!feof(fin) && !ferror(fin) && !ferror(fout));
	if (unlikely(ferror(fin) || ferror(fout))) {
		retv = errno;
		elog("Read/Write failed: %s\n", strerror(errno));
	}
	fclose(fin);
	fclose(fout);
	if (unlikely(retv||global_exit))
		goto exit_20;
	fin = fopen(tmpinit, "rb");
	fout = fopen("init", "wb");
	do {
		numbr = fread(res, 1, buflen, fin);
		if (numbr > 0) {
			numbw = fwrite(res, 1, numbr, fout);
			assert(numbw == numbr);
		}
	} while (!feof(fin) && !ferror(fin) && !ferror(fout));
	if (unlikely(ferror(fin)||ferror(fout))) {
		elog("Read/Write back to init script failed: %s\n",
				strerror(errno));
		retv = errno;
	}
	fclose(fin);
	fclose(fout);
	if (unlikely(retv != 0||global_exit))
		goto exit_20;

	printf("Assembling new initramfs for stateless OS...\n");
	sprintf(cmdbuf, "find . -print|cpio -o -H newc|gzip -c -9");
	retv = pipe_execute(res, RESLEN, cmdbuf, NULL, tmpramfs);
	if (unlikely(retv != 0||global_exit)) {
		elog("Assembling initramfs failed: %s\n", res);
		goto exit_20;
	}
	sprintf(cmdbuf, "mount -o remount -o rw /boot");
	retv = pipe_execute(res, RESLEN, cmdbuf, NULL, NULL);
	if (unlikely(retv != 0)) {
		elog("Cannot remount /boot to read-write: %s\n", res);
		goto exit_20;
	}
	printf("Updating %s...\n", initramfs);
	fout = fopen(initramfs, "wb");
	fin = fopen(tmpramfs, "rb");
	do {
		numbr = fread(res, 1, RESLEN, fin);
		if (numbr > 0) {
			numbw = fwrite(res, 1, numbr, fout);
			assert(numbw == numbr);
		}
	} while (!feof(fin) && !ferror(fin) && !ferror(fout));
	if (unlikely(ferror(fin) || ferror(fout))) {
		elog("Read/Write initramfs failed: %s\n", strerror(errno));
		retv = errno;
	}
	fclose(fin);
	fclose(fout);
	if (unlikely(retv||global_exit))
		goto exit_30;
	skgrub = 0;
	fin = fopen("/boot/grub/grub.cfg", "rb");
	fout = fopen(tmpgrub, "wb");
	do {
		numbr = getline(&res, &buflen, fin);
		if (strstr(res, "stateless")) {
			elog("/boot/grub/grub.cfg already set to stateless\n");
			skgrub = 1;
			break;
		}
		if (numbr > 0) {
			splash = strstr(res, "splash");
			if (splash) {
				strcpy(scratch, splash);
				strcpy(splash, "stateless ");
				strcat(splash, scratch);
				numbr += 10;
			}
			numbw = fwrite(res, 1, numbr, fout);
			assert(numbw == numbr);
		}
	} while (!feof(fin) && !ferror(fin) && !ferror(fout));
	if (unlikely(ferror(fin) || ferror(fout))) {
		elog("grub.cfg read/write failed: %s\n", strerror(errno));
		retv = errno;
	}
	fclose(fin);
	fclose(fout);
	if (unlikely(retv||global_exit))
		goto exit_30;

	if (!skgrub) {
		sysret = chmod("/boot/grub/grub.cfg", 0644);
		if (unlikely(sysret == -1)) {
			elog("Cannot change /boot/grub/grub.cfg to rw: %s\n",
					strerror(errno));
			retv = errno;
			goto exit_30;
		}
		fin = fopen(tmpgrub, "rb");
		fout = fopen("/boot/grub/grub.cfg", "wb");
		do {
			numbr = getline(&res, &buflen, fin);
			if (numbr > 0) {
				numbw = fwrite(res, 1, numbr, fout);
				assert(numbw == numbr);
			}
		} while (!feof(fin) && !ferror(fin) && !ferror(fout));
		if (unlikely(ferror(fin) || ferror(fout))) {
			elog("/boot/grub/grub.cfg read/write error: %s\n",
					strerror(errno));
			retv = errno;
		}
		fclose(fin);
		fclose(fout);
		if (unlikely(retv||global_exit))
			goto exit_30;
		sysret = chmod("/boot/grub/grub.cfg", 0444);
		if (unlikely(sysret == -1))
			elog("Cannot change /boot/grub/grub.cfg to ro\n");
	}
	printf("Migration to stateless OS complete\n");
	printf("Reboot is required for stateless OS to take effective\n");

exit_30:
	sprintf(cmdbuf, "mount -o remount -o ro /boot");
	retv = pipe_execute(res, RESLEN, cmdbuf, NULL, NULL);
	if (unlikely(retv != 0))
		elog("Cannot remount /boot to read-only: %s\n", res);

exit_20:
	unlink(tmpinit);
	unlink(tmpgrub);
	unlink(tmpramfs);
	if (unlikely(chdir(cwd) == -1)) {
		elog("Cannot change back to %s: %s\n", cwd, strerror(errno));
		retv = errno;
		goto exit_10;
	}
	sprintf(cmdbuf, "rm -rf %s", troot);
	retv = pipe_execute(res, RESLEN, cmdbuf, NULL, NULL);
	if (unlikely(retv))
		elog("Unable to remove %s: %s\n", troot, res);

exit_10:
	free(cwd);
	return retv;
}
