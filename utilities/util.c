#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <error.h>
#include <btrfs/kerncompat.h>
#include <linux/version.h>
#include "util.h"

struct nsinfo;

static int slow_copyfile(const char *from, const char *to, struct nsinfo *nsi)
{
	int err = -1;
	char *line = NULL;
	size_t n;
	FILE *from_fp, *to_fp;
	//struct nscookie nsc;

	//nsinfo__mountns_enter(nsi, &nsc);
	from_fp = fopen(from, "r");
	//nsinfo__mountns_exit(&nsc);
	if (from_fp == NULL)
		goto out;

	to_fp = fopen(to, "w");
	if (to_fp == NULL)
		goto out_fclose_from;

	while (getline(&line, &n, from_fp) > 0)
		if (fputs(line, to_fp) == EOF)
			goto out_fclose_to;
	err = 0;
out_fclose_to:
	fclose(to_fp);
	free(line);
out_fclose_from:
	fclose(from_fp);
out:
	return err;
}

int copyfile_offset(int ifd, loff_t off_in, int ofd, loff_t off_out, u64 size)
{
	void *ptr;
	loff_t pgoff;

	pgoff = off_in & ~(page_size - 1);
	off_in -= pgoff;

	ptr = mmap(NULL, off_in + size, PROT_READ, MAP_PRIVATE, ifd, pgoff);
	if (ptr == MAP_FAILED)
		return -1;

	while (size) {
		ssize_t ret = pwrite(ofd, ptr + off_in, size, off_out);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			break;

		size -= ret;
		off_in += ret;
		off_out += ret;
	}
	munmap(ptr, off_in + size);

	return size ? -1 : 0;
}

static int copyfile_mode_ns(const char *from, const char *to, mode_t mode,
			    struct nsinfo *nsi)
{
	int fromfd, tofd;
	struct stat st;
	int err;
	char *tmp = NULL, *ptr = NULL;
	//struct nscookie nsc;

	//nsinfo__mountns_enter(nsi, &nsc);
	err = stat(from, &st);
	//nsinfo__mountns_exit(&nsc);
	if (err)
		goto out;
	err = -1;

	/* extra 'x' at the end is to reserve space for '.' */
	if (asprintf(&tmp, "%s.XXXXXXx", to) < 0) {
		tmp = NULL;
		goto out;
	}
	ptr = strrchr(tmp, '/');
	if (!ptr)
		goto out;
	ptr = memmove(ptr + 1, ptr, strlen(ptr) - 1);
	*ptr = '.';

	tofd = mkstemp(tmp);
	if (tofd < 0)
		goto out;

	if (fchmod(tofd, mode))
		goto out_close_to;

	if (st.st_size == 0) { /* /proc? do it slowly... */
		err = slow_copyfile(from, tmp, nsi);
		goto out_close_to;
	}

	//nsinfo__mountns_enter(nsi, &nsc);
	fromfd = open(from, O_RDONLY);
	//nsinfo__mountns_exit(&nsc);
	if (fromfd < 0)
		goto out_close_to;

	err = copyfile_offset(fromfd, 0, tofd, 0, st.st_size);

	close(fromfd);
out_close_to:
	close(tofd);
	if (!err)
		err = link(tmp, to);
	unlink(tmp);
out:
	free(tmp);
	return err;
}

int copyfile_mode(const char *from, const char *to, mode_t mode)
{
	return copyfile_mode_ns(from, to, mode, NULL);
}

int copyfile(const char *from, const char *to)
{
	return copyfile_mode(from, to, 0755);
}

static ssize_t ion(bool is_read, int fd, void *buf, size_t n)
{
	void *buf_start = buf;
	size_t left = n;

	while (left) {
		/* buf must be treated as const if !is_read. */
		ssize_t ret =
			is_read ? read(fd, buf, left) : write(fd, buf, left);

		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			return ret;

		left -= ret;
		buf += ret;
	}

	BUG_ON((size_t)(buf - buf_start) != n);
	return n;
}

/*
 * Read exactly 'n' bytes or return an error.
 */
ssize_t readn(int fd, void *buf, size_t n)
{
	return ion(true, fd, buf, n);
}

/*
 * Write exactly 'n' bytes or return an error.
 */
ssize_t writen(int fd, const void *buf, size_t n)
{
	/* ion does not modify buf. */
	return ion(false, fd, (void *)buf, n);
}

void *proc_maps_get_addr(const char *comp)
{
	FILE *f = fopen("/proc/self/maps", "r");
	if (!f)
		error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
	char *line = NULL;
	size_t n = 0;
	ssize_t s = 0;
	char *addr = NULL;
	char *limit;
	char r, w, x, p;
	uint32_t off;
	unsigned char maj, min;
	unsigned long inode;
	while ((s = getline(&line, &n, f)) > 0) {
		line[s - 1] = '\0';
		int skip = 0;
		int ret = sscanf(line, proc_maps_fmt, &addr, &limit, &r, &w, &x,
				 &p, &off, &maj, &min, &inode, &skip);
		if (ret != 10)
			error(1, 0, "unable to parse proc maps");
		if (!strcmp(line + skip, comp))
			break;
	}
	free(line);
	fclose(f);
	return s > 0 ? addr : NULL;
}

static const char proc_maps_path_fmt[] =
	"/proc/%lu/maps";

void proc_maps_iterate(pid_t pid, void (*cb)(struct procmaps_entry*, void*), void *arg)
{
	char *line = NULL;
	size_t n = 0;
	ssize_t s = 0;
	FILE *f;
	if (pid) {
		int len = snprintf(NULL, 0, proc_maps_path_fmt, (unsigned long)pid);
		char path[len + 1];
		sprintf(path, proc_maps_path_fmt, (unsigned long)pid);
		f = fopen(path, "r");
	} else {
		f = fopen("/proc/self/maps", "r");
	}
	if (!f)
		error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
	while ((s = getline(&line, &n, f)) > 0) {
		line[s - 1] = '\0';
		struct procmaps_entry entry;
		int skip = 0;
		int ret = sscanf(line, proc_maps_fmt, &entry.addr, &entry.limit,
				 &entry.r, &entry.w, &entry.x, &entry.p, &entry.off,
				 &entry.maj, &entry.min, &entry.inode, &skip);
		if (ret != 10)
			error(1, 0, "unable to parse proc maps");
		entry.file = line + skip;
		cb(&entry, arg);
	}
	free(line);
	fclose(f);
}