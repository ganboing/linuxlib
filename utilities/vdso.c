#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <error.h>
#include <errno.h>
#include <assert.h>
#include <sys/utsname.h>
#include "util.h"
#include "vdso.h"

#ifndef static_assert
#define static_assert _Static_assert
#endif

#ifdef KERNEL_VERSION
#undef KERNEL_VERSION
#endif
//This is the wrong version that shipped with older libc/linux-api-headers
//#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
//This is the correct version
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))

typedef _Atomic(seq_t) atomic_seq_t;

#include "vdso-3.x.h"
#include "vdso-4.x.h"
#include "vdso-5.x.h"

typedef union vd_data {
	struct vsyscall_gtod_data3 vd3x;
	struct vsyscall_gtod_data4 vd4x;
	struct vdso_data5 vd5x;
	struct {
		seq_t seq;
	};
} vd_data;

static unsigned int linux_version;

static void __detect_linux_version(void) __attribute__((constructor));
static void __detect_linux_version(void)
{
	struct utsname un = {};
	if (uname(&un))
		error(1, errno, "failed to get uname");
	if (strcmp(un.sysname, "Linux"))
		error(1, 0, "not running on Linux");
	unsigned int a, b, c;
	int ret = sscanf(un.release, "%u.%u.%u", &a, &b, &c);
	if (ret != 3)
		error(1, 0, "unable to parse Linux version");
	linux_version = KERNEL_VERSION(a, b, c);
}

static unsigned vdso_format(void)
{
	if (linux_version < KERNEL_VERSION(4, 0, 0))
		return 0;
	if (linux_version < KERNEL_VERSION(4, 20, 0))
		return 1;
	return 2;
}

const vd_data *vdso_get_vd(void)
{
	char *vvar = proc_maps_get_addr("[vvar]");
#define VVAR_VD_OFFSET (0x80)
#define VVAR_ADDR (0ULL - 10 * 1024 * 1024 - 4096)
	if (!vvar)
		return (vd_data *)(VVAR_ADDR + VVAR_VD_OFFSET);
	return (vd_data *)(vvar + VVAR_VD_OFFSET);
#undef VVAR_ADDR
#undef VVAR_VD_OFFSET
}

static seq_t vdso_read_begin(const vd_common *vdc)
{
	seq_t seq;
	while ((seq = atomic_load((const atomic_seq_t *)vdc->seq)) & 1)
		__asm__ volatile("rep; nop" ::: "memory"); //PAUSE

	//could be smp_rmb, but acq_rel is the best we can do in C11
	atomic_thread_fence(memory_order_acq_rel);
	return seq;
}

static _Bool vdso_read_retry(const vd_common *vdc, seq_t start)
{
	seq_t seq;

	//could be smp_rmb, but acq_rel is the best we can do in C11
	atomic_thread_fence(memory_order_acq_rel);

	seq = atomic_load((const atomic_seq_t *)vdc->seq);
	return seq != start;
}

vd_common vdso_parse_vd(const vd_data *vd, unsigned clk)
{
	unsigned format = vdso_format();
	if (format > 2) {
		error(1, 0, "unsupported vdso format %d", format);
	}

	vd_common ret = {};
	ret.seq = &vd->seq;
	switch (format) {
	case 0:
		ret.clock_mode = &vd->vd3x.clock.vclock_mode;
		ret.sec = &vd->vd3x.wall_time_sec;
		ret.snsec = &vd->vd3x.wall_time_snsec;
		ret.cycle_last = &vd->vd3x.clock.cycle_last;
		ret.mask = &vd->vd3x.clock.mask;
		ret.mult = &vd->vd3x.clock.mult;
		ret.shift = &vd->vd3x.clock.shift;
		break;
	case 1:
		ret.clock_mode = &vd->vd4x.vclock_mode;
		ret.sec = &vd->vd4x.wall_time_sec;
		ret.snsec = &vd->vd4x.wall_time_snsec;
		ret.cycle_last = &vd->vd4x.cycle_last;
		ret.mask = &vd->vd4x.mask;
		ret.mult = &vd->vd4x.mult;
		ret.shift = &vd->vd4x.shift;
		break;
	case 2:
		ret.clock_mode = &vd->vd5x.clock_mode;
		ret.sec = &vd->vd5x.basetime[clk].sec;
		ret.snsec = &vd->vd5x.basetime[clk].nsec;
		ret.cycle_last = &vd->vd5x.cycle_last;
		ret.mask = &vd->vd5x.mask;
		ret.mult = &vd->vd5x.mult;
		ret.shift = &vd->vd5x.shift;
		break;
	}

	return ret;
}

void vdso_dump_vdc(FILE *f, const vd_common *vdc)
{
	fprintf(f,
		"vdso: clock_mode=%" PRIi32 " cycle_last=%" PRIu64
		" mask=%" PRIx64 " mult=%" PRIu32 " shift=%" PRIu32 "\n",
		*vdc->clock_mode, *vdc->cycle_last, *vdc->mask, *vdc->mult,
		*vdc->shift);
	fprintf(f, "vdso: cpu freq ~= %lluMHz\n",
		1000000ULL * (1ULL << *vdc->shift) / *vdc->mult);
	fprintf(f, "vdso: basetime = %" PRIu64 ".%" PRIu64 "\n", *vdc->sec,
		*vdc->snsec);
}

struct timespec vdso_timespec_from_vdc(const vd_common *vdc, u64 tsc)
{
	__int128 ns;
	struct timespec ret = { 0, 0 };
	seq_t seq;
	do {
		seq = vdso_read_begin(vdc);
		ns = (s64)tsc - (s64)*vdc->cycle_last;
		ns *= *vdc->mult;
		ns += *vdc->snsec;
		//vdc->snsec is not right shifted
		ns >>= *vdc->shift;

		ret.tv_sec = *vdc->sec;
		ret.tv_sec += ns / (1000UL * 1000 * 1000);
		ret.tv_nsec = ns % (1000UL * 1000 * 1000);
	} while (vdso_read_retry(vdc, seq));

	return ret;
}

void vdso_conversion_from_vdc(const vd_common *vdc, u32 *mult, u32 *shift,
			      s64 *offset)
{
	__int128 ns;
	seq_t seq;
	do {
		seq = vdso_read_begin(vdc);
		*mult = *vdc->mult;
		*shift = *vdc->shift;

		ns = *vdc->sec;
		ns *= 1000UL * 1000 * 1000;
		ns += *vdc->snsec >> *shift;
		//vdc->snsec is not right shifted

		*offset = ns - (((__int128)*vdc->cycle_last * *mult) >> *shift);
	} while (vdso_read_retry(vdc, seq));
}
