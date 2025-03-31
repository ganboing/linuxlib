#ifndef LINUXLIB_MISC_H
#define LINUXLIB_MISC_H

#include <errno.h>

struct scoped_fd {
	int fd;
	inline scoped_fd(int fd) : fd(fd)
	{}
	inline void release()
	{
		fd = -1;
	}
	inline ~scoped_fd()
	{
		if (fd >= 0)
			close(fd);
	}
};

#ifdef __cplusplus

#include <string>
#include <cstdio>
#include <cstdarg>

std::string cppfmt(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

inline std::string cppfmt(const char *fmt, ...)
{
	std::string ret;
	va_list vl;
	va_start(vl, fmt);
	int len = vsnprintf(nullptr, 0, fmt, vl);
	va_end(vl);
	if (!len)
		return ret;
	ret.resize(len);
	va_start(vl, fmt);
	vsprintf(&ret.front(), fmt, vl);
	va_end(vl);
	return ret;
}
#endif

#endif //LINUXLIB_MISC_H
