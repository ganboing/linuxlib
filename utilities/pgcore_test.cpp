#include <unistd.h>
#include <fcntl.h>
#include <cassert>
#include <error.h>
#include "pgcore.h"
#include "../common/misc.h"

extern "C" {
unsigned int page_size = getpagesize();
}

int main(int argc, char** argv){
	assert(argc > 1);
	pid_t pid = atoi(argv[1]);
	assert(pid > 0);
	int fd_out = open(cppfmt("core.%lu", (unsigned long)pid).c_str(), O_CREAT | O_EXCL | O_RDWR, S_IRWXU);
	assert(fd_out >= 0);
	proc_core core(pid);
	core.creat(fd_out);
	close(fd_out);
	return 0;
}