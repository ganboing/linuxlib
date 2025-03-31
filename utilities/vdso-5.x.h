struct vdso_timestamp {
	u64 sec;
	u64 nsec;
};
static_assert(sizeof(struct vdso_timestamp) == 16, "check sizeof");
struct vdso_data5 {
	u32 seq;
	s32 clock_mode;
	u64 cycle_last;
	u64 mask;
	u32 mult;
	u32 shift;
	struct vdso_timestamp basetime[12];
	s32 tz_minuteswest;
	s32 tz_dsttime;
	u32 hrtimer_res;
	u32 __unused;
};
static_assert(sizeof(struct vdso_data5) == 240, "check sizeof");
