#ifndef MY_LOG_H
#define MY_LOG_H

#include <unistd.h>
#include <cstdarg>
#include <cstdio>
#include "interceptors.h"

extern bool __mylog_enabled;

static inline void mylogv(const char *fmt, va_list vl) {
	if (!__mylog_enabled)
		return;
	va_list vl2;
	va_copy(vl2, vl);
	int len = vsnprintf(nullptr, 0, fmt, vl);
	char buff[len + 1];
	buff[len] = '\0';
	// need to use a new va_list
	vsnprintf(buff, len + 1, fmt, vl2);
	va_end(vl2);
	__write(2, buff, len);
}

static inline void mylog(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
static inline void mylog(const char *fmt, ...) {
	if (!__mylog_enabled)
		return;
	va_list vl;
	va_start(vl, fmt);
	mylogv(fmt, vl);
	va_end(vl);
}

static inline void mylogp(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
static inline void mylogp(const char *fmt, ...) {
	static const char prefix[] = "[TS_SHIM] ";
	if (!__mylog_enabled)
		return;
	__write(2, prefix, sizeof(prefix) - 1);
	va_list vl;
	va_start(vl, fmt);
	mylogv(fmt, vl);
	va_end(vl);
}

#endif
