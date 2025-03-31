#ifndef LINUXLIB_PERFTOOL_H
#define LINUXLIB_PERFTOOL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

//#define PERF_ALIGN(x, a) __PERF_ALIGN_MASK(x, (typeof(x))(a)-1)
//#define __PERF_ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))

typedef char s8;
typedef unsigned char u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef int32_t s32;
typedef uint32_t u32;
typedef int64_t s64;
typedef uint64_t u64;

extern bool dump_trace;
extern unsigned int page_size;

#ifndef offsetof
#define offsetof(TYPE, MEMBER)	__builtin_offsetof(TYPE, MEMBER)
#endif

#ifndef __force
#define __force
#endif

#ifndef __must_check
#define __must_check
#endif

#include "libperf_core.h"
#include "uapi_perf_event.h"
/* override system's version of linux/perf_event.h */
#define _LINUX_PERF_EVENT_H
#include "libperf_event.h"
#include "perf_record.h"
#include "perf_data.h"
#include "perf_tool.h"
#include "perf_session.h"
#include "perf_debug.h"
#include "linux_err.h"

static inline struct perf_session *perf_session__new_chk(struct perf_data *data,
						         struct perf_tool *tool)
{
	struct perf_session *s = perf_session__new(data, tool);
	if (!IS_ERR(s)) {
		return s;
	}
	errno = -PTR_ERR(s);
	return nullptr;
}

#endif
