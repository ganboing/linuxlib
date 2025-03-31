typedef unsigned long gtod_long_t;

struct vsyscall_gtod_data4 {
	u32 seq;
	s32 vclock_mode;
	u64 cycle_last;
	u64 mask;
	u32 mult;
	u32 shift;
	u64 wall_time_snsec;
	gtod_long_t wall_time_sec;
	gtod_long_t monotonic_time_sec;
	u64 monotonic_time_snsec;
	gtod_long_t wall_time_coarse_sec;
	gtod_long_t wall_time_coarse_nsec;
	gtod_long_t monotonic_time_coarse_sec;
	gtod_long_t monotonic_time_coarse_nsec;
	int tz_minuteswest;
	int tz_dsttime;
};
static_assert(sizeof(struct vsyscall_gtod_data4) == 104, "check sizeof");
