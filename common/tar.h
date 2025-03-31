#ifndef LINUXLIB_TAR_H
#define LINUXLIB_TAR_H

#include <filesystem>

struct stat;

void tar_begin(int fd_out);

void tar_writef(int fd_out, const char *data, off_t size);
void tar_copyf(int fd_out, int fd_in, off_t size, bool pipe);

void tar_file_mem_begin(int fd_out, const char *name, const struct stat *s);
void tar_file_mem_end(int fd_out, const struct stat *s);
void tar_file_mem(int fd_out, const char *name, const void *data,
		  const struct stat *);
bool tar_file_by_path(int fd_out, const char *name,
		      const std::filesystem::path &p, bool pipe, bool seqfile, bool allow_fail=false);
void tar_file_by_fd(int fd_out, const char *name, int fd, bool pipe);

void tar_end(int fd_out);

#endif //LINUXLIB_TAR_H
