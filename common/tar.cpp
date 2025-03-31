#include <filesystem>
#include <algorithm>
#include <functional>
#include <numeric>
#include <cstdint>
#include <cinttypes>
#include <cstdarg>
#include <error.h>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>
#include <ext/stdio_filebuf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include "tar.h"
#include "misc.h"

using namespace std;
using namespace std::filesystem;

struct TarHeader {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char checksum[7];
	char checksum_sp;
	char type;
	char linktarget[100];
	char _reserved[512 - 257];
};

static constexpr unsigned BSIZE = 512;

static_assert(sizeof(TarHeader) == BSIZE, "check TarHeader size");

static uint32_t checksum(const char *data, size_t len)
{
	return accumulate((unsigned char *)(data),
			  (unsigned char *)(data + len), 0, plus<uint32_t>());
}

static vector<char> _padding(BSIZE);

template <size_t N>
__attribute__((format(printf, 2, 3))) static void
fill_field(char (&f)[N], const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int n = vsnprintf(f, N, fmt, args);
	if (n < 0 || size_t(n) >= N)
		error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
	va_end(args);
}

void tar_writef(int fd_out, const char *data, off_t size)
{
	ssize_t ret;
	while (size) {
		ret = write(fd_out, data, size);
		if (ret <= 0 || ret > size)
			error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
		size -= ret;
		data += ret;
	}
}

void tar_copyf(int fd_out, int fd_in, off_t size, bool pipe)
{
	//static const off_t bs = 1UL * 1024 * 1024 * 1024; //1G
	ssize_t ret;
	off_t offset = 0;
	while (size) {
		ret = pipe ? splice(fd_in, &offset, fd_out, NULL, size, 0) :
			     sendfile(fd_out, fd_in, &offset, size);
		if (ret <= 0 || ret > size) {
			error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
		}
		size -= ret;
	}
}

static void tar_emit_header(int fd_out, const char *name,
			    const struct stat &statbuf)
{
	TarHeader h = {};
	fill_field(h.name, "%s", name);
	fill_field(h.mode, "%07" PRIo16, (uint16_t)(statbuf.st_mode));
	fill_field(h.uid, "%07" PRIo16, (uint16_t)(statbuf.st_uid));
	fill_field(h.gid, "%07" PRIo16, (uint16_t)(statbuf.st_gid));
	fill_field(h.size, "%011" PRIo64, (uint64_t)(statbuf.st_size));
	fill_field(h.mtime, "%011" PRIo64, (uint64_t)(statbuf.st_mtim.tv_sec));
	h.type = '0';
	fill_field(h.checksum, "%06" PRIo32,
		   checksum((char *)&h, sizeof(h)) + uint32_t(' ') * 8);
	h.checksum_sp = ' ';
	tar_writef(fd_out, (const char *)&h, sizeof(h));
}

void tar_file_by_fd(int fd_out, const char *name, int fd_in, bool pipe)
{
	struct stat statbuf = {};
	int ret = fstat(fd_in, &statbuf);
	if (ret < 0)
		error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
	tar_emit_header(fd_out, name, statbuf);
	tar_copyf(fd_out, fd_in, statbuf.st_size, pipe);
	tar_writef(fd_out, _padding.data(),
		   (statbuf.st_size + BSIZE - 1) / BSIZE * BSIZE -
			   statbuf.st_size);
}

void tar_file_mem_begin(int fd_out, const char *name, const struct stat *s)
{
	tar_emit_header(fd_out, name, *s);
}

void tar_file_mem_end(int fd_out, const struct stat *s)
{
	tar_writef(fd_out, _padding.data(),
		   (s->st_size + BSIZE - 1) / BSIZE * BSIZE - s->st_size);
}

void tar_file_mem(int fd_out, const char *name, const void *data,
		  const struct stat *s)
{
	tar_file_mem_begin(fd_out, name, s);
	tar_writef(fd_out, (const char *)data, s->st_size);
	tar_file_mem_end(fd_out, s);
}

bool tar_file_by_path(int fd_out, const char *name, const path &p, bool pipe,
		      bool seqfile, bool allow_fail)
{
	int fd = open(p.native().c_str(), O_RDONLY);
	if (fd < 0) {
		error(allow_fail ? 0 : 1, allow_fail ? 0 : errno,
		      "%s:%d open failed name=%s%s",
		      __FUNCTION__, __LINE__, p.native().c_str(),
		      allow_fail ? " (ignored)" : "");
		return false;
	}
	if (!seqfile) {
		// Can use splice/sendfile
		scoped_fd fd_in(fd);
		tar_file_by_fd(fd_out, name, fd, pipe);
		return true;
	}
	// Have to read the file into mem and tar it
	scoped_fd fd_in(fd);
	struct stat statbuf = {};
	int ret = fstat(fd, &statbuf);
	if (ret < 0)
		error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
	__gnu_cxx::stdio_filebuf<char> filebuf(fd, std::ios::in);
	fd_in.release(); // stdio_filebuf automatically releases the fd
	istream is(&filebuf);
	string f((istreambuf_iterator<char>(is)), istreambuf_iterator<char>());
	statbuf.st_size = f.size();
	tar_file_mem(fd_out, name, f.c_str(), &statbuf);
	return true;
}

void tar_begin(int fd_out)
{
}
void tar_end(int fd_out)
{
	tar_writef(fd_out, _padding.data(), BSIZE);
	tar_writef(fd_out, _padding.data(), BSIZE);
}