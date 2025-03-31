#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <error.h>
#include <memory>
#include <map>
#include <numeric>
#include <sys/sendfile.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <libelf.h>
#include "util.h"
#include "pgcore.h"
#include "../common/misc.h"

proc_core::proc_core(pid_t _pid) : pid(_pid)
{
	proc_maps_iterate(pid, [](procmaps_entry *entry, void *_self)
	{
		proc_core *self = (proc_core*)_self;
		if (entry->x != 'x')
			return;
		self->segments.emplace(entry->addr, entry->limit - entry->addr);
	}, this);
}

void proc_core::creat(int fd)
{
	Elf64_Ehdr ehdr = {};
	ehdr.e_ident[EI_MAG0] = ELFMAG0;
	ehdr.e_ident[EI_MAG1] = ELFMAG1;
	ehdr.e_ident[EI_MAG2] = ELFMAG2;
	ehdr.e_ident[EI_MAG3] = ELFMAG3;
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
#else
	ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
#endif
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
	ehdr.e_ident[EI_ABIVERSION] = 0;
	ehdr.e_type = ET_CORE;
#ifdef __x86_64__
	ehdr.e_machine = EM_X86_64;
#else
#error "unknown architecture"
#endif
	ehdr.e_version = EV_CURRENT;
	ehdr.e_phentsize = sizeof(Elf64_Phdr);
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_phnum = segments.size();
	ssize_t ret = writen(fd, &ehdr, sizeof(ehdr));
	if (ret < 0)
		error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
	Elf64_Phdr phdrs[segments.size()];
	size_t hdrsz = (sizeof(ehdr) + sizeof(phdrs) + page_size - 1)
		       / page_size * page_size, begin = hdrsz;
	size_t padding = hdrsz - sizeof(ehdr) - sizeof(phdrs);
	auto sit = segments.begin();
	for (size_t i = 0, j = segments.size(); i != j; ++i, ++sit)
	{
		phdrs[i].p_type = PT_LOAD;
		phdrs[i].p_flags = PF_R | PF_X;
		phdrs[i].p_offset = begin;
		phdrs[i].p_paddr = (Elf64_Addr)sit->first;
		phdrs[i].p_vaddr = (Elf64_Addr)sit->first;
		phdrs[i].p_filesz = sit->second;
		phdrs[i].p_memsz = sit->second;
		phdrs[i].p_align = 0;
		begin += sit->second;
	}
	ret = writen(fd, &phdrs, sizeof(phdrs));
	if (ret < 0)
		error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
	if (padding)
	{
		char pad[padding];
		memset(pad, 0, padding);
		ret = writen(fd, pad, padding);
		if (ret < 0)
			error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
	}
	std::unique_ptr<FILE, decltype(&fclose)> fmem(
		fopen(cppfmt("/proc/%lu/mem",
			     (unsigned long)pid).c_str(), "rb"), fclose);
	if (!fmem)
		error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
	for (auto &entry : segments)
	{
		void *buf = mmap(nullptr, entry.second,
				 PROT_READ|PROT_WRITE,
				 MAP_PRIVATE|MAP_ANONYMOUS,
				 -1, 0);
		if (buf == MAP_FAILED)
			error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
		off_t off = lseek(fileno(&*fmem), (uintptr_t)entry.first, SEEK_SET);
		if (off != (intptr_t)entry.first)
			error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
		ret = readn(fileno(&*fmem), buf, entry.second);
		if (ret < 0)
			error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
		ret = writen(fd, buf, entry.second);
		if (ret < 0)
			error(1, errno, "%s:%d", __FUNCTION__, __LINE__);
		munmap(buf, entry.second);
	}
}

size_t proc_core::size()
{
	size_t hdrsz = elf64_fsize(ELF_T_EHDR, 1, EV_CURRENT) +
		       elf64_fsize(ELF_T_PHDR, segments.size(), EV_CURRENT);
	assert(hdrsz == sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * segments.size());
	hdrsz = (hdrsz + page_size - 1) / page_size * page_size;
	size_t segsz = 0;
	segsz = std::accumulate(segments.begin(), segments.end(), segsz,
			[](size_t sum, const decltype(segments)::value_type& entry){
				return sum + entry.second;
			});
	return hdrsz + segsz;
}