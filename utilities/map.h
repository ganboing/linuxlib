/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_MAP_H
#define __PERF_MAP_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define ENTRY_TRAMPOLINE_NAME "__entry_SYSCALL_64_trampoline"

static inline bool is_entry_trampoline(const char *name)
{
	return !strcmp(name, ENTRY_TRAMPOLINE_NAME);
}

#endif /* __PERF_MAP_H */
