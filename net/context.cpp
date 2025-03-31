#include <cinttypes>
#include <cassert>
#include <error.h>
#include <ctime>
#include <cstddef>
#include <net/ethernet.h>
#include "context.h"
#include "log.h"

bool __print_sockaddr(const sockaddr* addr, socklen_t len, bool newline) {
	if (len < sizeof(sockaddr))
		return false;
	switch(addr->sa_family) {
	case AF_LOCAL: {
		mylog("LOCAL\n");
		break;
	}
	case AF_INET: {
		char buf[INET_ADDRSTRLEN];
		auto *addr_in = reinterpret_cast<const sockaddr_in*>(addr);
		inet_ntop(AF_INET, &addr_in->sin_addr, buf, sizeof(buf));
		mylog("IPv4 %s port %" PRIu16 "%s", buf, ntohs(addr_in->sin_port),
		      newline ? "\n" : "");
		break;
	}
	case AF_INET6: {
		char buf[INET6_ADDRSTRLEN];
		auto *addr_in6 = reinterpret_cast<const sockaddr_in6*>(addr);
		inet_ntop(AF_INET, &addr_in6->sin6_addr, buf, sizeof(buf));
		mylog("IPv6 %s port %" PRIu16 " flow %" PRIu32 " scope %" PRIu32 "%s", buf,
		      ntohs(addr_in6->sin6_port),
		      ntohl(addr_in6->sin6_flowinfo),
		      ntohl(addr_in6->sin6_scope_id),
		      newline ? "\n" : "");
		break;
	}
	case AF_PACKET: {
		auto *addr_ll = reinterpret_cast<const sockaddr_ll*>(addr);
		mylog("PACKET proto=%hu ifindex=%d hatype=%hu pkttype=%hhu\n",
		      addr_ll->sll_protocol,
		      addr_ll->sll_ifindex,
		      addr_ll->sll_hatype,
		      addr_ll->sll_pkttype);
		break;
	}
	default:
		mylog("unknown sa_family %hu\n", addr->sa_family);
		return false;
	}
	return true;
}

SockContext::SockContext(CaptureSession *_capture, int fd, int _domain, int _type, int _protocol) :
	  capture(_capture), domain(_domain), type(_type), protocol(_protocol), ts_flags(__get_ts_flags()) {
	struct hwtstamp_config hwconfig = {
		.flags = 0,
		.tx_type = HWTSTAMP_TX_ON,
		.rx_filter = HWTSTAMP_FILTER_ALL,
	};
	if (!ts_flags)
		return;
	if (__global_hwtm_dev) {
		mylogp("Enabling HW timestamping for device %s\n", __global_hwtm_dev);
		struct ifreq hwtstamp = {};
		hwtstamp.ifr_data = (char*)&hwconfig;
		strcpy(hwtstamp.ifr_name, __global_hwtm_dev);
		int rc = ioctl(fd, SIOCSHWTSTAMP, &hwtstamp);
		if (rc < 0){
			error(1, errno, "failed to enable HW timestamp");
		}
		mylogp("Enabled HW timestamp on dev %s, tx_type=%d, rx_filter=%d\n",
		       __global_hwtm_dev, hwconfig.tx_type, hwconfig.rx_filter);
	}
	// connectionless socket can enable timestamping now
	if (type == SOCK_DGRAM || type == SOCK_RAW)
		enable_ts(fd);
}

SockContext::~SockContext() {
	mylogp("socket %p released\n", this);
}

int SockContext::getpeername(int fd, sockaddr *addr, socklen_t *len) {
	int rc = __real_getpeername(fd, addr, len);
	errno_restorer er{};
	if (rc)
		return rc;
	if (type == SOCK_STREAM) {
		// Ensure timestamping
		mylogp("getpeername succeed, ensuring timestamping ");
		__print_sockaddr(addr, *len, true);
		ensure_ts(fd);
	}
	return rc;
}

int SockContext::getsockname(int fd, sockaddr *addr, socklen_t *len) {
	int rc = __real_getsockname(fd, addr, len);
	errno_restorer er{};
	if (type == SOCK_STREAM) {
		// Ensure timestamping
		//ensure_ts();
	}
	return rc;
}

int SockContext::connect(int fd, const struct sockaddr *addr, socklen_t len) {
	int rc = __real_connect(fd, addr, len);
	if (rc)
		return rc;
	errno_restorer er{};
	// connection socket can enable timestamping now
	if (type == SOCK_STREAM)
		enable_ts(fd);
	return rc;
}

int SockContext::bind(int fd, const struct sockaddr *addr, socklen_t len) {
	return __real_bind(fd, addr, len);
}

static inline uint64_t __tp2ns(timespec tp) {
	return uint64_t(tp.tv_sec) * 1000 * 1000 * 1000 + tp.tv_nsec;
}

void SockContext::capture_rxtx(const msghdr *msg, timespec devtime, size_t rx) {
	if (!capture)
		return;
	timespec usertime{};
	if (domain != AF_PACKET || type != SOCK_RAW || msg->msg_iovlen != 1)
		// TODO: support more domain/type combinations
		return;
	if (clock_gettime(CLOCK_REALTIME, &usertime))
		error(1, errno, "clock_gettime(REALTIME) failed");
	struct iovec *iov = msg->msg_iov;
	size_t len = rx ? rx : iov->iov_len;
	if (len < sizeof(L2Header))
		return;
	L2Header *l2 = (L2Header*)iov->iov_base;
	uint8_t *l2_payload = l2->L2Payload;
	uint16_t ethtype = l2->EthType;
	L2VlanHeader *l2v = nullptr;
	if (l2->EthType == htons(ETHERTYPE_VLAN) && len >= sizeof(L2VlanHeader)) {
		l2v = (L2VlanHeader *)l2;
		l2_payload = l2v->L2PayloadV;
		ethtype = l2v->EthTypeV;
	}
	CaptureFrame *frame = capture->reserve();
	if (rx) {
		frame->UserTime = __tp2ns(usertime) | 1;
		frame->DevTime = __tp2ns(devtime) | 1;
	} else if (devtime.tv_sec != 0 || devtime.tv_nsec != 0){
		// TX with device timestamp
		frame->UserTime = 0;
		frame->DevTime = __tp2ns(devtime) & ~uint64_t(1);
	} else {
		// TX without device timestamp
		frame->UserTime = __tp2ns(usertime) & ~uint64_t(1);
		frame->DevTime = 0;
	}
	frame->Size = len;
	memcpy(&frame->L2, l2, sizeof(L2Header));
	frame->VlanTCI = l2v ? l2v->VlanTCI : 0;
	frame->VlanEthType = l2v ? l2v->EthTypeV : 0;
	mylogp("capture: usertime=%" PRIu64 " devtime=%" PRIu64 " rx=%zu\n",
	       frame->UserTime, frame->DevTime, rx);
	switch(ntohs(ethtype)) {
	case 0x8892 /*PROFINET*/: {
		if (size_t((uint8_t*)iov->iov_base + len - l2_payload) <
		    sizeof(uint16_t) /*frameID*/ + sizeof(ProfinetCtrl))
			/* At least it should have a frameID + last 4 bytes for control */
			return;
		memcpy(&frame->Payload.Profinet.FrameID, l2_payload, sizeof(uint16_t));
		memcpy(&frame->Payload.Profinet.Ctrl,
		       (uint8_t*)iov->iov_base + len - sizeof(ProfinetCtrl), sizeof(ProfinetCtrl));
	}
	}
	capture->commit(frame);
}

#ifndef SCM_TIMESTAMPING_PKTINFO
#define SCM_TIMESTAMPING_PKTINFO 58

struct scm_ts_pktinfo {
	__u32 if_index;
	__u32 pkt_length;
	__u32 reserved[2];
};
#endif

std::pair<timespec, std::optional<uint32_t>> SockContext::extract_rxtx_ts(int fd, msghdr *msg, char *copyctrl, size_t *copylen) {
	struct cmsghdr *cm;
	struct scm_ts_pktinfo *pktinfo = nullptr;
	struct sock_extended_err *serr = nullptr;
	struct scm_timestamping *tss = nullptr;
	for (cm = CMSG_FIRSTHDR(msg); cm && cm->cmsg_len >= sizeof(cmsghdr);
	     cm = CMSG_NXTHDR(msg, cm)) {
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPING) {
			tss = (scm_timestamping*)CMSG_DATA(cm);
		} else if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPING_PKTINFO) {
			pktinfo = (scm_ts_pktinfo*)CMSG_DATA(cm);
			(void)pktinfo;
		} else if ((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_RECVERR) ||
			   (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_RECVERR) ||
			   (cm->cmsg_level == SOL_PACKET && cm->cmsg_type == PACKET_TX_TIMESTAMP)){
			serr = (sock_extended_err*)CMSG_DATA(cm);
			if (serr->ee_errno != ENOMSG ||
			    serr->ee_origin != SO_EE_ORIGIN_TIMESTAMPING ||
			    serr->ee_type != SCM_TSTAMP_SND) {
				error(1, 0, "Wrong serr received %u,%u,%u",
				      (unsigned)serr->ee_errno,
				      (unsigned)serr->ee_origin,
				      (unsigned)serr->ee_type);
			}
		} else if (copylen && *copylen >= CMSG_ALIGN(cm->cmsg_len)){
			/* copy the cmsg */
			memcpy(copyctrl, cm, CMSG_ALIGN(cm->cmsg_len));
			*copylen -= CMSG_ALIGN(cm->cmsg_len);
			copyctrl += CMSG_ALIGN(cm->cmsg_len);
		}
	}
	if (!tss) {
		// No timestamp
		return std::make_pair(timespec{0, 0}, std::nullopt);
	}
	mylogp("TIMESTAMP %2d [%" PRIu64 ".%" PRIu64 ","
	       " %" PRIu64 ".%" PRIu64 ","
	       " %" PRIi64 ".%" PRIu64 "]%s", fd,
	       (uint64_t)tss->ts[0].tv_sec, (uint64_t)tss->ts[0].tv_nsec,
	       (uint64_t)tss->ts[1].tv_sec, (uint64_t)tss->ts[1].tv_nsec,
	       (uint64_t)tss->ts[2].tv_sec, (uint64_t)tss->ts[2].tv_nsec,
	       serr ? " TX" : " RX\n");
	if (serr) {
		mylog(" code=%" PRIu8 " info=%" PRIu32 " data=%" PRIu32 "\n",
		      serr->ee_code,
		      serr->ee_info,
		      serr->ee_data);
	}
	return std::make_pair(
		(ts_flags & SOF_TIMESTAMPING_RAW_HARDWARE) ? tss->ts[2] : tss->ts[0],
		serr ? std::make_optional(serr->ee_data) : std::nullopt);
}

ssize_t SockContext::recvmsg(int fd, msghdr* msg, int flags) {
	// drain pending err queue
	char ctrl[1024];
	while(tx_timestamp_enabled()) {
		char eth_packet[1518];
		struct iovec iov {
			.iov_base = eth_packet,
			.iov_len = sizeof(eth_packet),
		};
		msghdr tmpmsg {
			.msg_name = nullptr,
			.msg_namelen = 0,
			.msg_iov = domain == AF_PACKET ? &iov : nullptr,
			.msg_iovlen = domain == AF_PACKET ? size_t(1) : 0,
			.msg_control = ctrl,
			.msg_controllen = sizeof(ctrl),
			.msg_flags = 0,
		};
		ssize_t rc = __real_recvmsg(fd, &tmpmsg, MSG_ERRQUEUE);
		if (rc < 0)
			break;
		if (tmpmsg.msg_iov) {
			// Should not happen
			if (size_t(rc) > tmpmsg.msg_iov->iov_len) {
				error(1, 0, "received more than buffer provided");
			}
			// "Fix" the iov_len
			tmpmsg.msg_iov->iov_len = rc;
		}
		auto tm_tskey = extract_rxtx_ts(fd, &tmpmsg);
		// TODO: use the tskey (tm_tskey.second)
		if (capture){
			capture_rxtx(&tmpmsg, tm_tskey.first, 0);
		}
	}
	// Copy of original ctrl/sz
	void *orig_ctrl = msg->msg_control;
	size_t orig_ctrlsz = msg->msg_controllen, orig_ctrlsz_left = orig_ctrlsz;
	msg->msg_control = ctrl;
	msg->msg_controllen = sizeof(ctrl);
	ssize_t rc = __real_recvmsg(fd, msg, flags);
	errno_restorer er{};
	if (rc > 0) {
		// While extracting the timestamp, filter all timestamp related cmsg and copy to original buffer
		auto tm_tskey = extract_rxtx_ts(fd, msg, (char*)orig_ctrl, &orig_ctrlsz_left);
		if (capture){
			capture_rxtx(msg, tm_tskey.first, rc);
		}
	}
	msg->msg_control = orig_ctrl;
	msg->msg_controllen = orig_ctrlsz - orig_ctrlsz_left;
	return rc;
}

ssize_t SockContext::sendmsg(int fd, const msghdr *msg, int flags) {
	if (capture && !tx_timestamp_enabled())
		// Capture userTime only
		capture_rxtx(msg, timespec{0, 0}, 0);
	return __real_sendmsg(fd, msg, flags);
}

void SockContext::ensure_ts(int fd) {
	unsigned int sockopt;
	socklen_t sockopt_len = sizeof(sockopt);
	int rc = __real_getsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING,
				   &sockopt, &sockopt_len);
	if (rc || sockopt_len != sizeof(sockopt)) {
		error(1, errno, "failed to getsockopt");
	}
	if (sockopt != ts_flags)
		enable_ts(fd);
}

void SockContext::enable_ts(int fd) {
	// enable timestamping
	unsigned sockopt = ts_flags;
	int rc = __real_setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING,
				   &sockopt, sizeof(sockopt));
	if (rc) {
		error(1, errno, "failed to enable timestamping");
	}
	mylogp("enabled timestamping for sock %d\n", fd);
}