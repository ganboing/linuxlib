#include <cstdlib>
#include <cstdio>
#include <cinttypes>
#include <string>
#include <error.h>
#include <filesystem>
#include <algorithm>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../common/tar.h"
#include "../common/misc.h"
#include "vdso.h"
#include "pgcore.h"

extern "C" {
#include <libelf.h>
}

extern "C" {
int kcore_copy(const char *from_dir, const char *sys_dir);
unsigned int page_size = getpagesize();
}

using namespace std;
using std::filesystem::directory_iterator;
using std::filesystem::is_directory;
using std::filesystem::path;

static option long_opts[] = { { "help", no_argument, nullptr, 'h' },
			      { "proc", required_argument, nullptr, 'p' },
			      { "sys", required_argument, nullptr, 's' },
			      { "prefix", required_argument, nullptr, 'r' },
			      { "pid", required_argument, nullptr, 'P' },
			      { "core", required_argument, nullptr, 'C' },
			      { "timeconv", no_argument, nullptr, 'T' },
			      { nullptr, 0, nullptr, 0 } };

static void help(const char *arg0)
{
	fprintf(stderr,
		"Usage: \n"
		"\t%s [OPTIONS...]\n"
		"\n"
		"\t-h, --help     Display help message\n"
		"\t-p, --proc     Path to procfs (default /proc)\n"
		"\t-s, --sys      Path to sysfs (default /sys)\n"
		"\t-r, --prefix   Prefix path for tarball\n"
		"\t-T, --timeconv Capture TSC <=> wall time conversion\n"
		"\t    --pid      Only collect procfs info for pid\n"
		"\t-C, --core     Capture core for process (with --pid)\n",
		arg0);
}

static void bundle_sysfs(const char *prefix, const char *sysfs, bool pipe)
{
	string sys_prefix = prefix ? string(prefix) + "sys" : "sys";
	path sysfs_path(sysfs);
	size_t sysfs_prefix_s = sysfs_path.native().size();
	{
		directory_iterator di(sysfs_path / "module");
		for (auto &m : di) {
			error_code ec;
			auto secdir = m.path() / "sections";
			if (!is_directory(secdir, ec))
				continue;
			directory_iterator mi_sec(secdir);
			for (auto &j : mi_sec) {
				tar_file_by_path(
					STDOUT_FILENO,
					(sys_prefix + j.path().native().substr(
							      sysfs_prefix_s))
						.c_str(),
					j.path(), pipe, true);
			}
			auto notesdir = m.path() / "notes";
			if (!is_directory(notesdir, ec))
				continue;
			directory_iterator mi_notes(notesdir);
			for (auto &j : mi_notes) {
				tar_file_by_path(
					STDOUT_FILENO,
					(sys_prefix + j.path().native().substr(
							      sysfs_prefix_s))
						.c_str(),
					j.path(), pipe, true);
			}
		}
	}
}

static void bundle_proc1(const path &p, const string &proc_prefix,
			 size_t procfs_prefix_s, bool pipe)
{
	auto proc = proc_prefix + p.native().substr(procfs_prefix_s);
	if (!tar_file_by_path(STDOUT_FILENO, (proc + "/maps").c_str(), p / "maps",
			 pipe, true, true) ||
	//tar_file_by_path(STDOUT_FILENO, (proc + "/status").c_str(),
	//		 p / "status", pipe, true);
	!tar_file_by_path(STDOUT_FILENO, (proc + "/auxv").c_str(), p / "auxv",
			 pipe, true, true)) {
		error(0, 0, "task doesn't exist, ignored (%s)",
		      p.c_str());
		return;
	}
	auto taskdir = p / "task";
	directory_iterator ti(taskdir);
	for (auto &j : ti) {
		auto task =
			proc_prefix + j.path().native().substr(procfs_prefix_s);
		tar_file_by_path(STDOUT_FILENO, (task + "/comm").c_str(),
				 j.path() / "comm", pipe, true);
		tar_file_by_path(STDOUT_FILENO, (task + "/status").c_str(),
				 j.path() / "status", pipe, true);
		tar_file_by_path(STDOUT_FILENO, (task + "/sched").c_str(),
				 j.path() / "sched", pipe, true);
	}
}

static void bundle_procfs(const char *prefix, const char *procfs, const char *sysfs,
			  unsigned long pid, bool core, bool pipe)
{
	string proc_prefix = prefix ? string(prefix) + "proc" : "proc";
	path procfs_path(procfs);
	if (!pid) {
		int kcoretmp = kcore_copy(procfs, sysfs);
		if (kcoretmp < 0)
			error(1, errno, "failed to copy kcore");
		scoped_fd fkcore(kcoretmp);
		tar_file_by_fd(STDOUT_FILENO, (proc_prefix + "/kcore").c_str(),
			       kcoretmp, pipe);
		tar_file_by_path(STDOUT_FILENO,
				 (proc_prefix + "/kallsyms").c_str(),
				 procfs_path / "kallsyms", pipe, true);
		tar_file_by_path(STDOUT_FILENO,
				 (proc_prefix + "/modules").c_str(),
				 procfs_path / "modules", pipe, true);
		tar_file_by_path(STDOUT_FILENO,
				 (proc_prefix + "/version").c_str(),
				 procfs_path / "version", pipe, true);
	}
	size_t procfs_prefix_s = procfs_path.native().size();
	if (!pid) {
		directory_iterator di(procfs_path);
		for (auto &p : di) {
			auto b = p.path().filename();
			auto &str_b = b.native();
			//directory is not for /proc/<pid>
			if (find_if_not(str_b.c_str(),
					str_b.c_str() + str_b.size(),
					[](char c) {
						return c >= '0' && c <= '9';
					}) != str_b.c_str() + str_b.size())
				continue;
			bundle_proc1(p.path(), proc_prefix, procfs_prefix_s, pipe);
		}
	} else {
		bundle_proc1(procfs_path / to_string(pid), proc_prefix,
			     procfs_prefix_s, pipe);
		if (core) {
			proc_core core(pid);
			struct stat statbuf = {};
			statbuf.st_mode = S_IRUSR;
			statbuf.st_size = core.size();
			tar_file_mem_begin(STDOUT_FILENO,
					   (proc_prefix + "/" + to_string(pid) + "/core").c_str(),
					   &statbuf);
			core.creat(STDOUT_FILENO);
			tar_file_mem_end(STDOUT_FILENO, &statbuf);
		}
	}
}

static void bundle_timecv(const char *prefix)
{
	string proc_prefix = prefix ? string(prefix) + "proc" : "proc";
	s64 offset;
	u32 mult, shift;
	vd_common vdc = vdso_parse_vd(vdso_get_vd(), CLOCK_REALTIME);
	vdso_conversion_from_vdc(&vdc, &mult, &shift, &offset);
	string timecv = cppfmt("tsc2walltime_mult: %" PRIu32
			       "\ntsc2walltime_shift: %" PRIu32
			       "\ntsc2walltime_offset: %" PRIi64 "\n",
			       mult, shift, offset);
	struct stat statbuf = {};
	statbuf.st_mode = S_IRUSR;
	statbuf.st_size = timecv.size();
	clock_gettime(CLOCK_REALTIME, &statbuf.st_mtim);
	tar_file_mem(STDOUT_FILENO,
		     (proc_prefix + "/tsc2walltime").c_str(),
		     timecv.c_str(), &statbuf);
}

int main(int argc, char **argv)
{
	int option_index = 0;
	const char *procfs = "/proc";
	const char *sysfs = "/sys";
	const char *prefix = nullptr;
	unsigned long pid = 0;
	bool timeconv = false;
	bool core = false;
	while (true) {
		int c = getopt_long(argc, argv, "hTCp:s:r:P:", long_opts,
				    &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h': {
			help(argv[0]);
			return 0;
		}
		case 'p': {
			procfs = optarg;
			break;
		}
		case 'P': {
			pid = strtoul(optarg, nullptr, 0);
			break;
		}
		case 's': {
			sysfs = optarg;
			break;
		}
		case 'r': {
			prefix = optarg;
			break;
		}
		case 'T': {
			timeconv = true;
			break;
		}
		case 'C' : {
			core = true;
			break;
		}
		default:
			return -1;
		}
	}
	//initialize libelf
	if (elf_version(EV_CURRENT) == EV_NONE) {
		return -2;
	}
	struct stat statbuf;
	int ret = fstat(fileno(stdout), &statbuf);
	if (ret < 0) {
		return ret;
	}
	bool pipe = S_ISFIFO(statbuf.st_mode);
	tar_begin(STDOUT_FILENO);
	if (!pid) {
		bundle_sysfs(prefix, sysfs, pipe);
	}
	bundle_procfs(prefix, procfs, sysfs, pid, core, pipe);
	if (timeconv) {
		bundle_timecv(prefix);
	}
	tar_end(STDOUT_FILENO);
	return 0;
}
