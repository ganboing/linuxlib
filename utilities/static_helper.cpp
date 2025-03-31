#include <cassert>
#include <cstring>
#include <cinttypes>
#include <climits>
#include <cstdarg>
#include <cstdlib>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <errno.h>

#include "static_helper.h"

extern "C" {
//void __assert_fail (const char *__assertion, const char *__file,
//			   unsigned int __line, const char *__function)
//__attribute__((visibility("default")));

#ifdef __x86_64__
unsigned long inline_syscall1(unsigned long nr, unsigned long a1) {
	unsigned long retval;
	asm volatile("syscall" : "=a"(retval) : "a" (nr), "D"(a1) : "rcx", "r11", "memory", "cc");
	return retval;
}

unsigned long inline_syscall3(unsigned long nr, unsigned long a1, unsigned long a2, unsigned long a3) {
	unsigned long retval;
	asm volatile("syscall" : "=a"(retval) : "a" (nr), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory", "cc");
	return retval;
}
#else
#error "unsupported architecture"
#endif

//syscalls

static unsigned long check_errno(unsigned long ret) {
	if (ret > (unsigned long)-4096) {
		//errno = ULONG_MAX - ret + 1;
		return (unsigned long)-1;
	}
	return ret;
}

int mprotect (void *__addr, size_t __len, int __prot) {
	auto ret = inline_syscall3(__NR_mprotect, (uintptr_t)__addr, __len, __prot);
	return (long)check_errno(ret);
}
ssize_t read(int fd, void *buf, size_t count){
	auto ret = inline_syscall3(__NR_read, fd, (uintptr_t)buf, count);
	return (long)check_errno(ret);
}
ssize_t write(int fd, const void *buf, size_t count) {
	auto ret = inline_syscall3(__NR_write, fd, (uintptr_t)buf, count);
	return (long)check_errno(ret);
}

int open(const char *pathname, int flags, ...) {
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list arg;
		va_start(arg, flags);
		mode = va_arg(arg, mode_t);
		va_end(arg);
	}
	auto ret = inline_syscall3(__NR_open, (uintptr_t)pathname, flags, mode);
	return (long)check_errno(ret);
}
int close(int fd) {
	auto ret = inline_syscall1(__NR_close, fd);
	return (long)check_errno(ret);
}

void report_fail (const char *__assertion, const char *__file,
		    const char *__line, const char *__function)
{
	static const char hdr[] = "FAIL: ";
	(void)write(2, hdr, sizeof hdr - 1);
	(void)write(2, __assertion, strlen(__assertion));
	static const char sep[] = " at ";
	(void)write(2, sep, sizeof sep - 1);
	(void)write(2, __file, strlen(__file));
	(void)write(2, ":", 1);
	(void)write(2, __line, strlen(__line));
	static const char sep2[] = " (";
	(void)write(2, sep2, sizeof sep2 - 1);
	(void)write(2, __function, strlen(__function));
	static const char sep3[] = ")\n";
	(void)write(2, sep3, sizeof sep3 - 1);
	inline_syscall1(__NR_exit_group, -1);
	__builtin_unreachable();
}

//size_t strlen(const char* str)
//__attribute__((visibility("default")));

size_t strlen(const char* str)
{
	size_t ret = 0;
	while(*str++){
		++ret;
	}
	return ret;
}
}

int myputs(const char* str) {
	write(1, str, strlen(str));
	write(1, "\n", 1);
	return 1;
}

extern "C" {
int memcmp(const void* a, const void* b, size_t n)
{
	uint8_t * s1 = (uint8_t*)a;
	uint8_t * s2 = (uint8_t*)b;
	for(; n--; ++s1, ++s2) {
		if (*s1 == *s2)
			continue;
		return *s1 < *s2 ? -1 : 1;
	}
	return 0;
}

int strcmp(const char* a, const char* b) {
	for(;;){
		auto x = *a++;
		auto y = *b++;
		if (x != y)
			return x < y ? -1 : 1;
		if (!x)
			return 0;
	}
}

void* memmove(void* dest, const void* src, size_t n) {
	char* d = (char*)dest;
	const char* s = (const char*)src;
	if (d < s) while (n--){
		*d++ = *s++;
	} else while(n--) {
		d[n] = s[n];
	}
	return dest;
}

static void iterate_seq(const char* path, char* buf, size_t len,
			bool(*cb)(char*, size_t, void*), void* priv = nullptr, char delim = '\0') {
	int fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		FAIL("unable to open environ");
	}
	//size_t off = 0;
	size_t toread = 0;
	bool skip = false;
	for(;;) {
		auto brk = std::find(buf, buf + toread, delim);
		//fill in till we can observe \0
		if (brk == buf + toread) {
			// \0 not found
			if (toread == len) {
				//no enough space to hold key=value
				skip = true;
				//puts(buf);
				toread = 0;
				continue;
			}
			ssize_t nread = read(fd, buf + toread, len - toread);
			if (nread < 0) {
				FAIL("read environ failed");
			} else if (nread) {
				//read something
				toread += nread;
				continue;
			} else if (toread) {
				//read nothing, but we haven't seen \0 yet
				FAIL("environ must end with \\0");
			} else {
				//read nothing, and nothing to process
				break;
			}
			__builtin_unreachable();
		}
		*brk++ = '\0';
		//puts(buf);
		if (!skip) {
			if(!cb(buf, brk - buf, priv))
				break;
		}
		skip = false;
		toread = buf + toread - brk;
		memmove(buf, brk, toread);
	}
	close(fd);
}

char *getenv(const char *name) {
	static char buf[128];
	struct _kv {
		const char* key;
		char* val;
	} kv = {name, nullptr};
	iterate_seq("/proc/self/environ", buf, sizeof buf, [](char* entry, size_t len, void* priv) {
			_kv* pkv = (_kv*)priv;
			auto sep = std::find(buf, buf + len, '=');
			if (sep == buf + len)
				return true;
			*sep++ = '\0';
			if (!strcmp(buf, pkv->key)) {
				pkv->val = sep;
				return false;
			}
			return true;
	}, &kv);
	return kv.val;
}

unsigned long getauxval(unsigned long type){
	int fd = open("/proc/self/auxv", O_RDONLY, 0);
	if (fd < 0) {
		FAIL("unable to open environ");
	}
	struct {
		unsigned long key;
		unsigned long val;
	}kv[32];
	for(;;) {
		ssize_t nread = read(fd, &kv, sizeof(kv));
		if (nread < 0) {
			FAIL("readling auxv failed");
		} else if (!nread) {
			break;
		} else if (nread % sizeof(kv[0])) {
			FAIL("auxv must be multiple of 2 * sizeof(unsigned long)");
		}
		for (size_t i = 0; i < nread / sizeof(kv[0]); ++i) {
			if (kv[i].key == type) {
				close(fd);
				return kv[i].val;
			}
		}
	}
	close(fd);
	return 0;
}

unsigned long strtoul( const char *str, char **str_end, int base ) {
	if (str_end != nullptr) {
		FAIL("str_end unsupported");
	}
	if (base != 10) {
		FAIL("only base 10 is supported");
	}
	//myputs(str);
	size_t len = strlen(str);
	unsigned long val = 0;
	while(len--) {
		char c = *str++;
		if (c < '0' || c > '9') {
			FAIL("invalid string for strtoul");
		}
		val *= 10;
		val += c - '0';
	}
	return val;
}

}