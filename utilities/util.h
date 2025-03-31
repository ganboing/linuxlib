/* SPDX-License-Identifier: GPL-2.0 */
#ifndef GIT_COMPAT_UTIL_H
#define GIT_COMPAT_UTIL_H

#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>

static const char proc_maps_fmt[] =
	"%p-%p %c%c%c%c %" PRIx32 " %hhx:%hhx %lu %n ";

struct procmaps_entry{
	char *addr;
	char *limit;
	char r, w, x, p;
	uint32_t off;
	unsigned char maj, min;
	unsigned long inode;
	char *file;
};

#ifdef __cplusplus
extern "C" {
#endif

extern unsigned int page_size;
int copyfile_mode(const char *from, const char *to, mode_t mode);
ssize_t readn(int fd, void *buf, size_t n);
ssize_t writen(int fd, const void *buf, size_t n);

//extern unsigned int linux_version;
void *proc_maps_get_addr(const char *comp);
void proc_maps_iterate(pid_t pid, void (*cb)(struct procmaps_entry *, void *),
		       void *arg);

#ifdef __cplusplus
}
#endif

#endif