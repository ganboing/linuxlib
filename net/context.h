#ifndef MY_CONTEXT_H
#define MY_CONTEXT_H

#include <atomic>
#include <cerrno>
#include <ctime>
#include <map>
#include <netpacket/packet.h>
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "capture.h"

extern const char *__global_hwtm_dev;
extern unsigned int __global_ts_flags;
extern uint64_t __global_ts_filter_dom;

bool __print_sockaddr(const sockaddr* addr, socklen_t len, bool newline=false);

struct errno_restorer {
	// save and restore errno
	errno_restorer() {
		__errno = errno;
	}
	~errno_restorer() {
		errno = __errno;
	}
	int __errno;
};

struct SockContext {
	SockContext(CaptureSession *_capture, int _fd, int _domain, int _type, int _protocol);
	~SockContext();
	inline static bool tx_timestamp_enabled() {
		return __global_ts_flags & (SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_TX_SOFTWARE);
	}
	inline unsigned int __get_ts_flags() {
		if (!tx_timestamp_enabled())
			return __global_ts_flags;
		// TX timestamp enabled
		if (domain == AF_PACKET)
			return __global_ts_flags;
		// Get the TX data for AF_PACKET, otherwise timestamp only
		return __global_ts_flags | SOF_TIMESTAMPING_OPT_TSONLY;
	}
	inline bool sockopt(int level, int optname, const void *optval, socklen_t optlen) {
		return false;
	}
	int getpeername(int fd, sockaddr *addr, socklen_t *len);
	int getsockname(int fd, sockaddr *addr, socklen_t *len);
	int bind(int fd, const struct sockaddr *addr, socklen_t len);
	int connect(int fd, const struct sockaddr *addr, socklen_t len);
	std::pair<timespec, std::optional<uint32_t>> extract_rxtx_ts(int fd, msghdr *msg, char *copyctrl = nullptr, size_t *copylen = 0);
	void capture_rxtx(const msghdr *msg, timespec devtime, size_t rx);
	ssize_t recvmsg(int fd, msghdr* msg, int flags);
	ssize_t sendmsg(int fd, const msghdr *msg, int flags);
	void ensure_ts(int fd);
	void enable_ts(int fd);
	CaptureSession *capture;
	const int domain;
	const int type;
	const int protocol;
	const unsigned int ts_flags;
};

#endif