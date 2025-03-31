#include <error.h>
#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include "vdso.h"

int main(int argc, char **argv)
{
	const vd_data *vd = vdso_get_vd();
	if (!vd) {
		error(1, 0, "unable to get vdso");
	}

	vd_common vdc = vdso_parse_vd(vd, CLOCK_REALTIME);
	if (*vdc.clock_mode != 1) {
		error(1, 0, "clocksource is not TSC, aborting");
	}
	vdso_dump_vdc(stdout, &vdc);
	if (argv[1])
		sleep(atoi(argv[1]));
	struct timespec gtod_tm = { 0, 0 };
	struct timespec calc_tm = { 0, 0 };

	u32 mult, shift;
	s64 offset;
	unsigned apicid;
	u64 tsc;

	int ret = clock_gettime(CLOCK_REALTIME, &gtod_tm);
	if (ret)
		error(2, errno, "clock_gettime failed");

	tsc = __builtin_ia32_rdtscp(&apicid);
	(void)apicid;
	calc_tm = vdso_timespec_from_vdc(&vdc, tsc);
	printf("gtod_tm = %lu.%lu\ncalc_tm = %lu.%lu\n", (long)gtod_tm.tv_sec,
	       (long)gtod_tm.tv_nsec, (long)calc_tm.tv_sec,
	       (long)calc_tm.tv_nsec);
	printf("TSC = %" PRIu64 "\n", tsc);
	printf("difference (ns) over %d seconds: %ld\n",
	       argv[1] ? atoi(argv[1]) : 0,
	       (long)((__int128)calc_tm.tv_sec * 1000 * 1000 * 1000 +
		      calc_tm.tv_nsec -
		      (__int128)gtod_tm.tv_sec * 1000 * 1000 * 1000 -
		      gtod_tm.tv_nsec));

	vdso_conversion_from_vdc(&vdc, &mult, &shift, &offset);
	printf("clock = TSC * %" PRIu32 " >> %" PRIu32 " %c %" PRIi64 "\n",
	       mult, shift, offset < 0 ? '-' : '+',
	       offset < 0 ? -offset : offset);
	__int128 lhs = (((__int128)tsc * mult) >> shift) + offset;
	__int128 rhs =
		(__int128)calc_tm.tv_sec * 1000 * 1000 * 1000 + calc_tm.tv_nsec;
	if (abs(lhs - rhs) > 1) {
		error(3, 0, "invalid conversion");
	}

	time_t since = offset / 1000 / 1000 / 1000;
	struct tm lt = {};
	gmtime_r(&since, &lt);
	char buff[256];
	strftime(buff, sizeof(buff), "Booted since ~ %F %T", &lt);
	puts(buff);
	return 0;
}
