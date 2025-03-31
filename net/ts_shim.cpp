#include <cassert>
#include <cstring>
#include <climits>
#include <error.h>
#include <mutex>
#include <memory>
#include <map>
#include <unordered_map>
#include <string_view>
#include <errno.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include "interceptors.h"
#include "log.h"
#include "spin_lock.h"
#include "context.h"
#include "capture.h"

#if 0
void __print_msg(const msghdr *msg) {
	mylogp("MSG: ");
	__print_sockaddr((sockaddr*)msg->msg_name, msg->msg_namelen, true);
}
#endif

struct __init_marker_pre {
	bool deinit = false;
	~__init_marker_pre() {
		deinit = true;
	}
} __init_marker_pre{};

bool __mylog_enabled = !!getenv("TS_SHIM_LOGGING");
bool __global_disable = [](){
	char *exe_name = getenv("TS_SHIM_EXE_NAME");
	if (!exe_name)
		return false;
	char path[PATH_MAX] = "";
	int fd = open("/proc/self/cmdline", O_RDONLY);
	if (fd < 0) {
		error(1, errno, "unable to open cmdline");
	}
	ssize_t rc = read(fd, path, sizeof(path));
	if (rc <= 0) {
		error(1, errno, "unable to read cmdline");
	}
	__close(fd);
	path[rc - 1] = '\0';
	const char *base = basename(path);
	bool disabled = !!strcmp(base, exe_name);
	if (disabled) {
		error(0, 0, "TS_SHIM disabled (via TS_SHIM_EXE_NAME), self=%s", base);
	}
	return disabled;
}();

uint64_t __global_ts_filter_dom = __global_disable ? 0 : []() {
	char *savedptr, *flags = getenv("TS_SHIM_DOM_FILTER");
	uint64_t domains = 0;
	if (flags)
		for (char *opt = strtok_r(flags, ",", &savedptr); opt != nullptr;
			opt = strtok_r(nullptr, ",", &savedptr)) {
			if (opt == "packet"sv) {
				domains |= (uint64_t(1) << AF_PACKET);
			}
		}
	return domains;
}();

unsigned int __global_ts_flags = __global_disable ? 0 : [](){
	char *savedptr, *flags = getenv("TS_SHIM_TMSTAMPING");
	bool tx = false, hw = false;
	if (flags) for (char *opt = strtok_r(flags, ",", &savedptr); opt != nullptr;
				opt = strtok_r(nullptr, ",", &savedptr)) {
		if (opt == "tx"sv) {
			tx = true;
		} else if (opt == "hw"sv) {
			hw = true;
		}
	}
	unsigned int ts_flags = hw ?
		SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE:
		SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
	if (tx) {
		ts_flags |= hw ?
			SOF_TIMESTAMPING_TX_HARDWARE :
			SOF_TIMESTAMPING_TX_SOFTWARE;
		ts_flags |= SOF_TIMESTAMPING_OPT_CMSG |
			SOF_TIMESTAMPING_OPT_ID |
			(1<<13); //SOF_TIMESTAMPING_OPT_PKTINFO;
	}
	return ts_flags;
}();

const char *__global_hwtm_dev = __global_disable ? nullptr : getenv("TS_SHIM_HW_DEV");

std::map<uintptr_t, std::shared_ptr<SharedObjDesc> > __loaded_so_segments;
std::map<std::string_view, std::shared_ptr<SharedObjDesc> > __loaded_solibs;
static std::unordered_map<int, std::shared_ptr<SockContext>> ctx_repo;
static MySpinLock ctx_repo_lock;

#ifndef SHM_HUGE_SHIFT
#define SHM_HUGE_SHIFT 26
#endif

#ifndef SHM_HUGE_2MB
#define SHM_HUGE_2MB (21 << SHM_HUGE_SHIFT)
#endif

static CaptureSession *capture_session = __global_disable ? nullptr : [](){
	const char *str_buff_order = getenv("TS_SHIM_BUFF_ORDER");
	if (!str_buff_order)
		return (CaptureSession*)nullptr;
	const char *str_buff_tag = getenv("TS_SHIM_BUFF_TAG");
	if (!str_buff_tag)
		return (CaptureSession*)nullptr;
	unsigned long buff_order = strtoul(str_buff_order, nullptr, 10);
	if (buff_order > 30) {
		// only allow <= 1G buffers
		error(1, 0, "buffer too large, check TS_SHIM_BUFF_ORDER");
	}
	static_assert(sizeof(key_t) >= 4, "check sizeof(key_t)");
	key_t tag = 0;
	memcpy(&tag, str_buff_tag, std::min(sizeof(key_t), strlen(str_buff_tag)));
	int h_ctrl = shmget(tag, sizeof(CaptureBufferCtrl), IPC_CREAT | 0600);
	if (h_ctrl < 0)
		error(1, errno, "failed to create/find shm for control");
	void *mapped_ctrl = shmat(h_ctrl, NULL, 0);
	if (mapped_ctrl == MAP_FAILED)
		error(1, errno, "failed to map shm for control");
	int h_buff = shmget(tag ^ 1, size_t(1) << buff_order,
	       IPC_CREAT | SHM_HUGETLB | SHM_HUGE_2MB | 0600);
	if (h_buff < 0)
		error(1, errno, "failed to create/find shm for buffer");
	void *mapped_buff = shmat(h_buff, NULL, 0);
	if (mapped_buff == MAP_FAILED)
		error(1, errno, "failed to map shm for buffer");
	return new CaptureSession((CaptureBufferCtrl*)mapped_ctrl, (CaptureFrame*)mapped_buff,
				  (size_t(1) << buff_order) / sizeof(CaptureFrame));
}();

static std::shared_ptr<SockContext> create_sock_ctx(int fd, int domain, int type, int protocol) {
	auto ptr = std::make_shared<SockContext>(capture_session, fd, domain, type, protocol);
	std::lock_guard<MySpinLock> l(ctx_repo_lock);
	auto i = ctx_repo.emplace(fd, std::move(ptr));
	if (!i.second) {
		error(1, 0, "socket %d already exists", fd);
	}
	return i.first->second;
}

static void clone_sock_ctx(int newfd, std::shared_ptr<SockContext> ctx) {
	std::lock_guard<MySpinLock> l(ctx_repo_lock);
	auto i = ctx_repo.emplace(newfd, std::move(ctx));
	if (!i.second) {
		error(1, 0, "socket %d already exists (clone)", newfd);
	}
}

static std::shared_ptr<SockContext> find_sock_ctx(int fd) {
	std::lock_guard<MySpinLock> l(ctx_repo_lock);
	auto i = ctx_repo.find(fd);
	std::shared_ptr<SockContext> ctx = i != ctx_repo.end() ? i->second : nullptr;
	return ctx;
}

static void del_sock_ctx(int fd) {
	std::lock_guard<MySpinLock> l(ctx_repo_lock);
	auto i = ctx_repo.find(fd);
	if (i == ctx_repo.end())
		return;
	mylogp("removing ctx of socket %d, ctx=%p\n", fd, i->second.get());
	i = ctx_repo.erase(i);
}

static inline const char *__domain_str(int domain)
{
	static const std::map<int, const char*> _m = {
		{AF_UNIX, "AF_UNIX"},
		{AF_INET, "AF_INET"},
		{AF_INET6, "AF_INET6"},
		{AF_PACKET, "AF_PACKET"},
	};
	auto i = _m.find(domain);
	return  i != _m.end() ? i->second : nullptr;
}

static inline const char *__type_str(int type)
{
	static const std::map<int, const char*> _m = {
		{SOCK_STREAM, "SOCK_STREAM"},
		{SOCK_DGRAM, "SOCK_DGRAM"},
		{SOCK_RAW, "SOCK_RAW"},
		{SOCK_PACKET, "SOCK_PACKET"},
	};
	auto i = _m.find(type);
	return  i != _m.end() ? i->second : nullptr;
}

static inline const char *__protocol_str(int protocol)
{
	static const std::map<int, const char*> _m = {
		{0, "ip"},
		{1, "icmp"},
		{6, "tcp"},
		{17, "udp"},
	};
	auto i = _m.find(protocol);
	return  i != _m.end() ? i->second : nullptr;
}

struct __init_marker_post {
	bool init;
	__init_marker_post() {
		__interceptors_init();
		init = true;
	}
} __init_marker_post{};

static bool __chk_alive() {
	if (!__init_marker_post.init)
		return false;
	if (__init_marker_pre.deinit)
		return false;
	return true;
}
static void __assert_alive(const char *func, void *retaddr) {
	if (__chk_alive())
		return;
	usleep(10UL * 1000 * 1000);
	error(1, 0, "%s called before interceptors init or after deinit, caller=%p",
	      func, retaddr);
}

ssize_t do_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	const int supported_flags =
		MSG_CMSG_CLOEXEC | MSG_ERRQUEUE | MSG_DONTWAIT | MSG_WAITALL | MSG_PEEK;
	int left_flags = flags & ~supported_flags;
	if (left_flags) {
		error(1, 0, "socket %d recvmsg with unsupported flags %x", sockfd, left_flags);
	}
	auto ctx = find_sock_ctx(sockfd);
	if (!ctx)
		return __real_recvmsg(sockfd, msg, flags);
	return ctx->recvmsg(sockfd, msg, flags);
}
static_assert(std::is_same<decltype(&do_recvmsg), decltype(&recvmsg)>::value, "check do_recvmsg type");

ssize_t do_recvfrom(int sockfd, void *buf, size_t n, int flags,
		    struct sockaddr *addr, socklen_t *len)
{
	const int supported_flags = MSG_DONTWAIT | MSG_WAITALL | MSG_PEEK;
	int left_flags = flags & ~supported_flags;
	if (left_flags) {
		error(1, 0, "socket %d recv with unsupported flags %x", sockfd, left_flags);
	}
	iovec iov= {.iov_base = buf, .iov_len = n};
	sockaddr_storage sockaddr_stor;
	msghdr msg {
		.msg_name = &sockaddr_stor,
		.msg_namelen = sizeof(sockaddr_stor),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = nullptr,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	ssize_t rc = do_recvmsg(sockfd, &msg, flags);
	if (!len)
		return rc;
	memcpy(addr, &sockaddr_stor, std::min(*len, msg.msg_namelen));
	*len = msg.msg_namelen;
	return rc;
}
static_assert(std::is_same<decltype(&do_recvfrom), decltype(&recvfrom)>::value, "check do_recvfrom type");

ssize_t do_sendmsg(int sockfd, const msghdr *msg, int flags)
{
	const int supported_flags =
		MSG_CONFIRM | MSG_DONTROUTE | MSG_DONTWAIT | MSG_EOR | MSG_MORE | MSG_NOSIGNAL | MSG_FASTOPEN;
	int left_flags = flags & ~supported_flags;
	if (left_flags) {
		error(1, 0, "socket %d sendmsg with unsupported flags %x", sockfd, left_flags);
	}
	for(auto cm = CMSG_FIRSTHDR(msg);
	     cm && cm->cmsg_len >= sizeof(cmsghdr);
	     cm = CMSG_NXTHDR(const_cast<msghdr*>(msg), cm)) {
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_TIMESTAMPING) {
			error(1, 0, "app is requesting per msg based timestamping, this it not supported right now");
		}
	}
	auto ctx = find_sock_ctx(sockfd);
	if (!ctx)
		return __real_sendmsg(sockfd, msg, flags);
	return ctx->sendmsg(sockfd, msg, flags);
}
static_assert(std::is_same<decltype(&do_sendmsg), decltype(&sendmsg)>::value, "check sendmsg type");

ssize_t do_sendto(int sockfd, const void *buf, size_t n, int flags,
	       const struct sockaddr *addr, socklen_t len)
{
	const int supported_flags =
		MSG_CONFIRM | MSG_DONTROUTE | MSG_DONTWAIT | MSG_EOR | MSG_MORE | MSG_NOSIGNAL | MSG_FASTOPEN;
	int left_flags = flags & ~supported_flags;
	if (left_flags) {
		error(1, 0, "socket %d send with unsupported flags %x", sockfd, left_flags);
	}
	iovec iov= {.iov_base = const_cast<void*>(buf), .iov_len = n};
	msghdr msg {
		.msg_name = const_cast<sockaddr*>(addr),
		.msg_namelen = len,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = nullptr,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	return do_sendmsg(sockfd, &msg, flags);
}
static_assert(std::is_same<decltype(&do_sendto), decltype(&sendto)>::value, "check do_sendto type");

#pragma GCC visibility push(default)
extern "C" {

ssize_t send (int sockfd, const void *buf, size_t n, int flags)
{
	__assert_alive(__func__, __builtin_return_address(0));
	if (__global_disable) {
		return __real_send(sockfd, buf, n, flags);
	}
	//mylog("sending %zu bytes %p to fd %d, flags=%x\n", n, buf, sockfd, flags);
	return do_sendto(sockfd, buf, n, flags, nullptr, 0);
}

ssize_t recv (int sockfd, void *buf, size_t n, int flags)
{
	__assert_alive(__func__, __builtin_return_address(0));
	if (__global_disable) {
		return __real_recv(sockfd, buf, n, flags);
	}
	ssize_t rc = do_recvfrom(sockfd, buf, n, flags, nullptr, nullptr);
	errno_restorer er{};
	//mylog("recvd %zd bytes %p from fd %d, flags=%x\n", rc, buf, sockfd, flags);
	return rc;
}

ssize_t sendto (int sockfd, const void *buf, size_t n, int flags,
	       const struct sockaddr *addr, socklen_t len)
{
	__assert_alive(__func__, __builtin_return_address(0));
	if (__global_disable) {
		return __real_sendto(sockfd, buf, n, flags, addr, len);
	}
	//mylog("sending %zu bytes %p to fd %d, flags=%x, addr=%p\n", n, buf, sockfd, flags, addr);
	return do_sendto(sockfd, buf, n, flags, addr, len);
}

ssize_t recvfrom(int sockfd, void *buf, size_t n, int flags,
		 struct sockaddr *addr, socklen_t *len)
{
	__assert_alive(__func__, __builtin_return_address(0));
	if (__global_disable) {
		return __real_recvfrom(sockfd, buf, n, flags, addr, len);
	}
	ssize_t rc = do_recvfrom(sockfd, buf, n, flags, addr, len);
	errno_restorer er{};
	//mylog("recvd %zd bytes %p from fd %d, flags=%x, addr=%p\n", rc, buf, sockfd, flags, addr);
	return rc;
}

ssize_t sendmsg(int sockfd, const msghdr *msg, int flags)
{
	__assert_alive(__func__, __builtin_return_address(0));
	if (__global_disable) {
		return __real_sendmsg(sockfd, msg, flags);
	}
	return do_sendmsg(sockfd, msg, flags);
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	__assert_alive(__func__, __builtin_return_address(0));
	if (__global_disable) {
		return __real_recvmsg(sockfd, msg, flags);
	}
	return do_recvmsg(sockfd, msg, flags);
}
#if 0
ssize_t read (int fd, void *buf, size_t n)
{
	if (!__ts_shim_initialized)
		return __real_read(fd, buf, n);
	auto ctx = find_sock_ctx(fd);
	if (!ctx)
		return __real_read(fd, buf, n);
	return do_recvfrom(fd, buf, n, 0, nullptr, 0);
}

ssize_t write (int fd, const void *buf, size_t n)
{
	if (!__ts_shim_initialized)
		return __real_write(fd, buf, n);
	auto ctx = find_sock_ctx(fd);
	if (!ctx)
		return __real_write(fd, buf, n);
	return do_sendto(fd, buf, n, 0, nullptr, 0);
}
#endif
int bind(int sockfd, const struct sockaddr *addr, socklen_t len)
{
	__assert_alive(__func__, __builtin_return_address(0));
	if (__global_disable) {
		return __real_bind(sockfd, addr, len);
	}
	mylogp("bind %d to ", sockfd);
	__print_sockaddr(addr, len, true);
	auto ctx = find_sock_ctx(sockfd);
	if (!ctx)
		return __real_bind(sockfd, addr, len);
	return ctx->bind(sockfd, addr, len);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t len)
{
	__assert_alive(__func__, __builtin_return_address(0));
	if (__global_disable) {
		return __real_connect(sockfd, addr, len);
	}
	mylogp("connect sock %d to ", sockfd);
	__print_sockaddr(addr, len, true);
	auto ctx = find_sock_ctx(sockfd);
	if (!ctx)
		return __real_connect(sockfd, addr, len);
	return ctx->connect(sockfd, addr, len);
}

int socket(int domain, int type, int protocol)
{
	__assert_alive(__func__, __builtin_return_address(0));
	int fd = __real_socket(domain, type, protocol);
	if (__global_disable)
		return fd;
	errno_restorer er{};
	if (fd < 0) {
		return fd;
	}
	if (__global_ts_filter_dom && (__global_ts_filter_dom & (uint64_t(1) << domain)) == 0)
		return fd;
	uintptr_t caller = (uintptr_t)__builtin_return_address(0);
	auto desc = __find_so_desc((void*)caller);
	if (desc && desc->name == LIBNAME_GLIBC) {
		mylogp("ignoring socket created within libc\n");
		return fd;
	}
	if (desc && desc->name == LIBNAME_RESOLV) {
		mylogp("ignoring socket created within libresolv\n");
		return fd;
	}
	const char *str_t = __type_str(type);
	const char *str_d = __domain_str(domain);
	const char *str_p = __protocol_str(protocol);
	mylogp("creating socket of domain %d%s%s%s, type %d%s%s%s, protocol %d%s%s%s, fd=%d\n",
	      domain,   str_d ? " (" : "", str_d ? str_d : "", str_d ? ")" : "",
	      type,     str_t ? " (" : "", str_t ? str_t : "", str_t ? ")" : "",
	      protocol, str_p ? " (" : "", str_p ? str_p : "", str_p ? ")" : "",
	      fd);
	auto ptr = create_sock_ctx(fd, domain, type, protocol);
	mylogp("created ctx for socket %d @ %p\n", fd, ptr.get());
	return fd;
}

int close(int fd)
{
	if (__chk_alive())
		return __close(fd);
	if (__global_disable)
		return __close(fd);
	//mylog("closing %d\n", fd);
	del_sock_ctx(fd);
	return __close(fd);
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	__assert_alive(__func__, __builtin_return_address(0));
	if (__global_disable) {
		return __real_setsockopt(fd, level, optname, optval, optlen);
	}
	mylogp("setsockopt %d, level=%d, optname=%d, optval=%p, optlen=%u\n",
	      fd, level, optname, optval, (unsigned)optlen);
	auto ctx = find_sock_ctx(fd);
	if (!ctx)
		return __real_setsockopt(fd, level, optname, optval, optlen);
	if (!ctx->sockopt(level, optname, optval, optlen))
		return __real_setsockopt(fd, level, optname, optval, optlen);
	errno = 0;
	return 0;
}

extern int getpeername(int fd, sockaddr *addr, socklen_t *len)
{
	__assert_alive(__func__, __builtin_return_address(0));
	if (__global_disable) {
		return __real_getpeername(fd, addr, len);
	}
	auto ctx = find_sock_ctx(fd);
	if (!ctx)
		return __real_getpeername(fd, addr, len);
	return ctx->getpeername(fd, addr, len);
}

extern int getsockname(int fd, sockaddr *addr, socklen_t *len)
{
	__assert_alive(__func__, __builtin_return_address(0));
	if (__global_disable) {
		return __real_getsockname(fd, addr, len);
	}
	auto ctx = find_sock_ctx(fd);
	if (!ctx)
		return __real_getsockname(fd, addr, len);
	return ctx->getsockname(fd, addr, len);
}

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif

#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif

#ifndef F_GET_RW_HINT
#define F_GET_RW_HINT 1035
#endif

#ifndef F_SET_RW_HINT
#define F_SET_RW_HINT 1036
#endif

#ifndef F_GET_FILE_RW_HINT
#define F_GET_FILE_RW_HINT 1037
#endif

#ifndef F_SET_FILE_RW_HINT
#define F_SET_FILE_RW_HINT 1038
#endif

static int __dup_sockfd(int fd, int newfd)
{
	if (newfd < 0)
		return newfd;
	auto ctx = find_sock_ctx(fd);
	if (!ctx)
		return newfd;
	mylogp("cloning sockfd %d to %d\n", fd, newfd);
	clone_sock_ctx(newfd, ctx);
	return newfd;
}

extern int fcntl (int fd, int cmd, ...)
{
	va_list vl;
	va_start(vl, cmd);
	switch (cmd) {
	case F_DUPFD /*int*/:
	case F_DUPFD_CLOEXEC /*int*/: {
		int rc = __fcntl(fd, cmd, va_arg(vl, int));
		if (!__chk_alive() || __global_disable)
			return rc;
		return __dup_sockfd(fd, rc);
	}
	case F_GETFD /*void*/:
		return __fcntl(fd, cmd);
	case F_SETFD /*int*/:
		return __fcntl(fd, cmd, va_arg(vl, int));
	case F_GETFL /*void*/:
		return __fcntl(fd, cmd);
	case F_SETFL /*int*/:
		return __fcntl(fd, cmd, va_arg(vl, int));
	case F_SETLK /*struct flock**/:
	case F_SETLKW /*struct flock**/:
	case F_GETLK /*struct flock**/:
	case F_OFD_SETLK /*struct flock**/:
	case F_OFD_SETLKW /*struct flock**/:
	case F_OFD_GETLK /*struct flock**/:
		return __fcntl(fd, cmd, va_arg(vl, void*));
	case F_GETOWN /*void*/:
		return __fcntl(fd, cmd);
	case F_SETOWN /*int*/:
		return __fcntl(fd, cmd, va_arg(vl, int));
	case F_GETOWN_EX /*struct f_owner_ex**/:
	case F_SETOWN_EX /*struct f_owner_ex**/:
		return __fcntl(fd, cmd, va_arg(vl, void*));
	case F_GETSIG /*void*/:
		return __fcntl(fd, cmd);
	case F_SETSIG /*int*/:
		return __fcntl(fd, cmd, va_arg(vl, int));
	case F_SETLEASE /*int*/:
		return __fcntl(fd, cmd, va_arg(vl, int));
	case F_GETLEASE /*void*/:
		return __fcntl(fd, cmd);
	case F_NOTIFY /*int*/:
		return __fcntl(fd, cmd, va_arg(vl, int));
	case F_SETPIPE_SZ /*int*/:
		return __fcntl(fd, cmd, va_arg(vl, int));
	case F_GETPIPE_SZ /*void*/:
		return __fcntl(fd, cmd);
	case F_ADD_SEALS /*int*/:
		return __fcntl(fd, cmd, va_arg(vl, int));
	case F_GET_SEALS /*void*/:
		return __fcntl(fd, cmd);
	case F_GET_RW_HINT /*uint64_t**/:
	case F_SET_RW_HINT /*uint64_t**/:
	case F_GET_FILE_RW_HINT /*uint64_t**/:
	case F_SET_FILE_RW_HINT /*uint64_t**/:
		return __fcntl(fd, cmd, va_arg(vl, void*));
	default:
		error(1, 0, "unknown fcntl cmd %d", cmd);
	}
	__builtin_unreachable();
}

extern int dup (int fd)
{
	int rc = __fcntl(fd, F_DUPFD, 0);
	if (!__chk_alive() || __global_disable)
		return rc;
	return __dup_sockfd(fd, rc);
}

extern int dup2 (int fd, int fd2)
{
	int rc = __dup2(fd, fd2);
	if (!__chk_alive() || __global_disable)
		return rc;
	return __dup_sockfd(fd, rc);
}

extern int dup3 (int fd, int fd2, int flags)
{
	int rc = __dup2(fd, fd2);
	if (rc >= 0 && (flags & O_CLOEXEC)) {
		if (__fcntl(rc, F_SETFD, FD_CLOEXEC) < 0) {
			error(1, errno, "failed to set FD_CLOEXEC on newly duped fd %d", rc);
		}
	}
	if (!__chk_alive() || __global_disable)
		return rc;
	return __dup_sockfd(fd, rc);
}
}
#pragma GCC visibility pop