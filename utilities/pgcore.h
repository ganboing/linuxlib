#ifndef LINUXLIB_PGCORE_H
#define LINUXLIB_PGCORE_H

#include <map>
#include <unistd.h>

struct proc_core {
	const pid_t pid;
	std::map<char*, size_t> segments;
	proc_core(pid_t _pid);
	void creat(int fd);
	size_t size();
};

#endif //LINUXLIB_PGCORE_H
