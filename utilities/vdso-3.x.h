typedef unsigned long gtod_long_t;

struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

#if 0
struct timespec {
	time_t tv_sec;
	long   tv_nsec;
};
#endif

struct vsyscall_gtod_data3 {
	u32 seq;
	struct {
		int vclock_mode;
		u64 cycle_last;
		u64 mask;
		u32 mult;
		u32 shift;
	} clock;
	u64 wall_time_sec;
	u64 wall_time_snsec;
	u64 monotonic_time_snsec;
	u64 monotonic_time_sec;

	struct timezone sys_tz;
	struct timespec wall_time_coarse;
	struct timespec monotonic_time_coarse;
};
static_assert(sizeof(struct vsyscall_gtod_data3) == 112, "check sizeof");
