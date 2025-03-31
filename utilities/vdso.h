#ifndef __PERF_VDSO_H
#define __PERF_VDSO_H

#include <stdint.h>
#include <stdio.h>

union vd_data;
typedef union vd_data vd_data;

typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;
typedef u32 seq_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vd_common {
	const seq_t *seq;
	const s32 *clock_mode;
	const u64 *sec;
	const u64 *snsec;
	const u64 *cycle_last;
	const u64 *mask;
	const u32 *mult;
	const u32 *shift;
} vd_common;

const vd_data *vdso_get_vd();
vd_common vdso_parse_vd(const vd_data *vd, unsigned clk);
void vdso_dump_vdc(FILE *f, const vd_common *vdc);
struct timespec vdso_timespec_from_vdc(const vd_common *vd, u64 tsc);
void vdso_conversion_from_vdc(const vd_common *vdc, u32 *mult, u32 *shift,
			      s64 *offset);

#ifdef __cplusplus
}
#endif

#endif
