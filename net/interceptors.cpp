#include <map>
#include <memory>
#include <cassert>
#include <link.h>
#include <dlfcn.h>
#include <error.h>
#include "interceptors.h"
#include "log.h"

TypeofBind __real_bind;
//TypeofClose __real_close;
TypeofSocket __real_socket;
TypeofConnect __real_connect;
TypeofSetSockOpt __real_setsockopt;
TypeofGetSockOpt __real_getsockopt;

TypeofRecv __real_recv;
TypeofRecvMsg __real_recvmsg;
TypeofRecvFrom __real_recvfrom;

TypeofSend __real_send;
TypeofSendTo __real_sendto;
TypeofSengMsg __real_sendmsg;

TypeofGetPeerName __real_getpeername;
TypeofGetSockName __real_getsockname;

//TypeofDup __real_dup;
//TypeofDup2 __real_dup2;
//TypeofDup3 __real_dup3;
//TypeofFcntl __real_fcntl;

//TypeofRead __real_read;
//TypeofWrite __real_write;

#define GLIBC_VER_216 "GLIBC_2.16"
#define GLIBC_VER_225 "GLIBC_2.2.5"
#define GLIBC_VER_29 "GLIBC_2.9"

static void *__libc_handle;
static void *__libresolv_handle;

static void *real_func_addr(void *handle, const char *name,
			    const char *ver= nullptr, bool allow_fail=false) {
	void *addr = ver ? dlvsym(handle, name, ver) : dlsym(handle, name);
	if (!addr && !allow_fail) {
		error(1, 0, "dl(v)sym failed for %s: %s", name, dlerror());
	}
	return addr;
}

std::shared_ptr<SharedObjDesc> __find_so_desc(void* ptr)
{
	uintptr_t p = (uintptr_t)ptr;
	// .... such that value < element
	auto i = __loaded_so_segments.upper_bound(p);
	if (i == __loaded_so_segments.begin())
		return nullptr;
	auto desc = (--i)->second; // move io prev element
	assert(i->first >= desc->base);
	p -= desc->base;
	auto j = desc->segments.find(i->first - desc->base);
	assert(j != desc->segments.end()); // must be found
	assert(p >= j->first);
	return p - j->first < j->second /* within segment range */ ? desc : nullptr;
}

#define __chk_real_function1(func, libname) do {	\
        auto desc = __find_so_desc((void*)__real_ ## func);	\
        if (!desc) error(1, 0, "chk_real: "			\
		"function %s is not from any solib", #func);	\
        if (desc->name != libname) error(1, 0, "chk_real: "	\
		"function %s is in %.*s, expected %.*s", #func,	\
		int(desc->name.size()), desc->name.data(),	\
		int(libname.size()), libname.data());		\
} while (0)

#define __chk_real_function2(func, libname0, libname1) do {	\
        auto desc = __find_so_desc((void*)__real_ ## func);	\
        if (!desc) error(1, 0, "chk_real: "			\
		"function %s is not from any solib", #func);	\
        if (desc->name != libname0 && desc->name != libname1)	\
		error(1, 0, "chk_real: function %s is in %.*s, "\
		"expected %.*s or %.*s", #func,			\
		int(desc->name.size()), desc->name.data(),	\
		int(libname0.size()), libname0.data(),		\
		int(libname1.size()), libname1.data());		\
} while (0)


void __interceptors_init() {
	// Use __read
	//__real_read = (TypeofRead)real_func_addr(RTLD_NEXT, "read", GLIBC_VER_225);
	// User __write
	//__real_write = (TypeofWrite)real_func_addr(RTLD_NEXT, "write", GLIBC_VER_225);

	dl_iterate_phdr([](struct dl_phdr_info *info, size_t size, void*){
		assert(size >= sizeof(dl_phdr_info));
		mylogp("shared library %s loaded @%p%s\n",
		       info->dlpi_name, (void*)info->dlpi_addr, info->dlpi_name[0] ? "" : " (ignored)");
		if (!info->dlpi_name[0])
			return 0;
		auto desc = std::make_shared<SharedObjDesc>(info->dlpi_addr, info->dlpi_name);
		//error(0, 0, "%s", desc->name.data());
		__loaded_solibs.emplace(desc->name, desc);
		//error(1, 0, "%s", desc->name.data());
		for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
			auto &phdr = info->dlpi_phdr[i];
			// Only interested in LOAD segments
			if(phdr.p_type != PT_LOAD)
				continue;
			// Only interested in X segment
			if((phdr.p_flags & PF_X) == 0)
				continue;
			assert(phdr.p_vaddr == phdr.p_paddr);
			// Not a absolute address
			assert(phdr.p_vaddr < 0x10000000ULL);
			desc->segments.emplace(phdr.p_vaddr, phdr.p_memsz);
			auto res = __loaded_so_segments.emplace(phdr.p_vaddr + info->dlpi_addr, desc);
			if (!res.second)
				error(1, 0,
				      "dl_iterate_phdr: vaddr %p already taken", (char*)phdr.p_vaddr + info->dlpi_addr);
		}
		return 0;
	}, nullptr);
	auto i = __loaded_solibs.find(LIBNAME_GLIBC);
	if (i == __loaded_solibs.end()) {
		error(1, 0, "libc not loaded, can't continue");
	}
	auto j = __loaded_solibs.find(LIBNAME_RESOLV);
	if (j == __loaded_solibs.end()) {
		error(1, 0, "libresolv not loaded, is the library built correctly?");
	}
	__libc_handle = dlopen(i->second->path.c_str(), RTLD_NOLOAD);
	__libresolv_handle = dlopen(j->second->path.c_str(), RTLD_NOLOAD);
	__real_bind = (TypeofBind)real_func_addr(__libc_handle, "bind", GLIBC_VER_225);
	// Use __close
	//__real_close = (TypeofClose)real_func_addr(__libc_handle, "close", GLIBC_VER_225);
	__real_socket = (TypeofSocket)real_func_addr(__libc_handle, "socket", GLIBC_VER_225);
	__real_connect = (TypeofConnect)real_func_addr(__libc_handle, "connect", GLIBC_VER_225);
	__real_setsockopt = (TypeofSetSockOpt)real_func_addr(__libc_handle, "setsockopt", GLIBC_VER_225);
	__real_getsockopt = (TypeofGetSockOpt)real_func_addr(__libc_handle, "getsockopt", GLIBC_VER_225);
	__real_recv = (TypeofRecv)real_func_addr(__libc_handle, "recv", GLIBC_VER_225);
	__real_recvmsg = (TypeofRecvMsg)real_func_addr(__libc_handle, "recvmsg", GLIBC_VER_225);
	__real_recvfrom = (TypeofRecvFrom)real_func_addr(__libc_handle, "recvfrom", GLIBC_VER_225);
	__real_send = (TypeofSend)real_func_addr(__libc_handle, "send", GLIBC_VER_225);
	__real_sendto = (TypeofSendTo)real_func_addr(__libc_handle, "sendto", GLIBC_VER_225);
	__real_sendmsg = (TypeofSengMsg)real_func_addr(__libc_handle, "sendmsg", GLIBC_VER_225);
	__real_getsockname = (TypeofGetSockName)real_func_addr(__libc_handle, "getsockname", GLIBC_VER_225);
	__real_getpeername = (TypeofGetPeerName)real_func_addr(__libc_handle, "getpeername", GLIBC_VER_225);
	__chk_real_function1(bind, LIBNAME_GLIBC);
	//__chk_real_function2(close, LIBNAME_GLIBC, LIBNAME_PTHREAD);
	__chk_real_function1(socket, LIBNAME_GLIBC);
	__chk_real_function2(connect, LIBNAME_GLIBC, LIBNAME_PTHREAD);
	__chk_real_function1(setsockopt, LIBNAME_GLIBC);
	__chk_real_function1(getsockopt, LIBNAME_GLIBC);
	__chk_real_function2(recv, LIBNAME_GLIBC, LIBNAME_PTHREAD);
	__chk_real_function2(recvmsg, LIBNAME_GLIBC, LIBNAME_PTHREAD);
	__chk_real_function2(recvfrom, LIBNAME_GLIBC, LIBNAME_PTHREAD);
	__chk_real_function2(send, LIBNAME_GLIBC, LIBNAME_PTHREAD);
	__chk_real_function2(sendto, LIBNAME_GLIBC, LIBNAME_PTHREAD);
	__chk_real_function2(sendmsg, LIBNAME_GLIBC, LIBNAME_PTHREAD);
	__chk_real_function1(getsockname, LIBNAME_GLIBC);
	__chk_real_function1(getpeername, LIBNAME_GLIBC);

	//__chk_real_function2(read, LIBNAME_GLIBC, LIBNAME_PTHREAD);
	//__chk_real_function2(write, LIBNAME_GLIBC, LIBNAME_PTHREAD);

	// Use __fcntl
	// __real_dup = (TypeofDup)real_func_addr(__libc_handle, "dup", GLIBC_VER_225);
	// Use __dup2
	// __real_dup2 = (TypeofDup2)real_func_addr(__libc_handle, "dup2", GLIBC_VER_225);
	// Use __dup2 + __fcntl
	// __real_dup3 = (TypeofDup3)real_func_addr(__libc_handle, "dup3", GLIBC_VER_29);
	// Use __fcntl
	// __real_fcntl = (TypeofFcntl)real_func_addr(__libc_handle, "fcntl", GLIBC_VER_225);
	// __chk_real_function1(dup, LIBNAME_GLIBC);
	//__chk_real_function1(dup2, LIBNAME_GLIBC);
	//__chk_real_function1(dup3, LIBNAME_GLIBC);
	//__chk_real_function2(fcntl, LIBNAME_GLIBC, LIBNAME_PTHREAD);
#if 0
	// following bounds are only heuristics
	__libc_low = (uintptr_t)real_func_addr("__libc_init_first", GLIBC_VER_225);
	__libc_high = (uintptr_t)real_func_addr("__libc_freeres", GLIBC_VER_225);
	__libresolv_low = std::min(
			(uintptr_t)real_func_addr("_sethtent", GLIBC_VER_225, true),
			(uintptr_t)real_func_addr("__dn_expand", GLIBC_VER_225, true));
	__libresolv_high = (uintptr_t)real_func_addr("_res_opcodes", GLIBC_VER_225, true);
#endif
}