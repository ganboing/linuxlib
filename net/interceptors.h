#ifndef MY_INTERCEPTORS_H
#define MY_INTERCEPTORS_H

#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <cstring>
#include <string>
#include <memory>
#include <map>
#include <type_traits>

struct SharedObjDesc{
	const uintptr_t base;
	const std::string path;
#ifdef basename
#error "You are using the wrong version of basename"
#endif
	const std::string_view name = ::basename(path.c_str());
	std::map<uintptr_t, size_t> segments = {};
	SharedObjDesc(uintptr_t b, std::string p) : base(b), path(std::move(p)) {}
};

extern std::map<uintptr_t, std::shared_ptr<SharedObjDesc> > __loaded_so_segments;
extern std::map<std::string_view, std::shared_ptr<SharedObjDesc> > __loaded_solibs;

using namespace std::literals::string_view_literals;
static const std::string_view LIBNAME_GLIBC = "libc.so.6"sv;
static const std::string_view LIBNAME_RESOLV = "libresolv.so.2"sv;
static const std::string_view LIBNAME_PTHREAD = "libpthread.so.0"sv;

extern "C" {
using TypeofBind = decltype(&bind);
//using TypeofClose = decltype(&close);
using TypeofSocket = decltype(&socket);
using TypeofConnect = decltype(&connect);
using TypeofSetSockOpt = decltype(&setsockopt);
using TypeofGetSockOpt = decltype(&getsockopt);
extern TypeofBind __real_bind;
//extern TypeofClose __real_close;
extern int __close(int __fd);
static_assert(std::is_same<decltype(&__close), decltype(&close)>::value,
	      "check typeof __close");
extern TypeofSocket __real_socket;
extern TypeofConnect __real_connect;
extern TypeofSetSockOpt __real_setsockopt;
extern TypeofGetSockOpt __real_getsockopt;

using TypeofRecv = decltype(&recv);
using TypeofRecvMsg = decltype(&recvmsg);
using TypeofRecvFrom = decltype(&recvfrom);
extern TypeofRecv __real_recv;
extern TypeofRecvMsg __real_recvmsg;
extern TypeofRecvFrom __real_recvfrom;

using TypeofSend = decltype(&send);
using TypeofSendTo = decltype(&sendto);
using TypeofSengMsg = decltype(&sendmsg);
extern TypeofSend __real_send;
extern TypeofSendTo __real_sendto;
extern TypeofSengMsg __real_sendmsg;

using TypeofGetPeerName = decltype(&getpeername);
using TypeofGetSockName = decltype(&getsockname);
extern TypeofGetPeerName __real_getpeername;
extern TypeofGetSockName __real_getsockname;

extern int __dup2(int __fd, int __fd2) __THROW;
static_assert(std::is_same<decltype(&__dup2), decltype(&dup2)>::value,
	      "check typeof __dup2");
extern int __fcntl(int __fd, int __cmd, ...);
static_assert(std::is_same<decltype(&__fcntl), decltype(&fcntl)>::value,
	      "check typeof __fcntl");
//using TypeofDup = decltype(&dup);
//using TypeofDup2 = decltype(&dup2);
//using TypeofDup3 = decltype(&dup3);
//using TypeofFcntl = decltype(&fcntl);
//extern TypeofDup __real_dup;
//extern TypeofDup2 __real_dup2;
//extern TypeofDup3 __real_dup3;
//extern TypeofFcntl __real_fcntl;

extern ssize_t __read(int __fd, void *__buf, size_t __nbytes);
static_assert(std::is_same<decltype(&__read), decltype(&read)>::value,
	      "check typeof __read");
extern ssize_t __write(int __fd, const void *__buf, size_t __n);
static_assert(std::is_same<decltype(&__write), decltype(&write)>::value,
	      "check typeof __write");
//using TypeofRead = decltype(&read);
//using TypeofWrite = decltype(&write);
//extern TypeofRead __real_read;
//extern TypeofWrite __real_write;
}

void __interceptors_init();
std::shared_ptr<SharedObjDesc> __find_so_desc(void* ptr);

#endif
