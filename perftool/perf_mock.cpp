#include <memory>
#include <cassert>
#include <error.h>
#include <sanitizer/lsan_interface.h>
extern "C" {
#include "libperftool.h"
}

using namespace std;

#if 0
#include "perf_lsan_suppressions.h"
extern "C" __attribute__((no_sanitize_address))
__attribute__((no_sanitize_memory)) __attribute__((no_sanitize_thread))
__attribute__((visibility("default"))) __attribute__((used)) const char *
__lsan_default_suppressions()
{
	return perf_lsan_default_suppressions;
}
#endif

static int libperf_print(enum libperf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main()
{
	perf_debug_setup();
	libperf_init(libperf_print);
	dump_trace = true;
	struct perf_data pd {};
	pd.mode = PERF_DATA_MODE_READ;
	struct perf_tool pt {};
	pt.ordered_events = true;
	unique_ptr<struct perf_session, decltype(&perf_session__delete)> session(
		perf_session__new_chk(&pd, &pt), &perf_session__delete);
	if (!session) {
		error(1, errno, "failed to create session");
	}
	int err = perf_session__process_events(&*session);
	return err;
}
