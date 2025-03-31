#ifndef LINUXLIB_STATIC_HELPER_H
#define LINUXLIB_STATIC_HELPER_H

extern "C" {
void report_fail(const char *, const char *, const char *, const char *)
	__attribute__((noreturn));
};
#define xstr(s) str(s)
#define str(s) #s
#define FAIL(reason) \
	report_fail(reason, __FILE__, xstr(__LINE__), __FUNCTION__)

#endif //LINUXLIB_STATIC_HELPER_H
