/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_SYMBOL
#define __PERF_SYMBOL 1

#include <btrfs/kerncompat.h>
#include <stdbool.h>

int kcore_copy(const char *from_dir /*, const char *to_dir*/, const char *sys_dir);

static inline bool symbol__restricted_filename(const char *filename,
					       const char *restricted_filename)
{
	return false;
}

int modules__parse(const char *procdir, const char *sysdir, void *arg,
		   int (*process_module)(void *arg, const char *name, u64 start,
					 u64 size, u64 lastaddr));

typedef int (*mapfn_t)(u64 start, u64 len, u64 pgoff, void *data);

#endif