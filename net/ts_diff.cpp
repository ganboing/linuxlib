#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cinttypes>
#include <string_view>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <queue>
#include <unordered_set>
#include <map>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "capture.h"

#define DEFAULT_HIST_SEC 10

//static std::string_view run_type;

struct DissectedFrame {
	uint16_t Size;
	L2Header L2;
	CapturePayload Payload;
};

static bool supported_frame(const CaptureFrame& frame) {
	uint16_t ethtype = frame.L2.EthType;
	if (ntohs(frame.L2.EthType) == ETHERTYPE_VLAN) {
		ethtype = frame.VlanEthType;
	}
	switch(ntohs(ethtype)) {
	case 0x8892:
		return true;
	}
	return false;
}

static uint64_t get_frame_time(const CaptureFrame& frame) {
	if (!frame.DevTime && !frame.UserTime)
		error(1, 0, "No time received on frame");
	return frame.DevTime ? frame.DevTime : frame.UserTime;
}

static bool is_tx_frame(const CaptureFrame& frame) {
	return !(get_frame_time(frame) & 1);
}

static std::pair<CaptureFrameDissected, std::optional<uint16_t>> dissect_frame(const CaptureFrame& frame) {
	CaptureFrameDissected ret = {};
	std::optional<uint16_t> vlanTCI;
	ret.Size = frame.Size;
	memcpy(&ret.L2, &frame.L2, sizeof(L2Header));
	if (ntohs(frame.L2.EthType) == ETHERTYPE_VLAN) {
		ret.Size -= 4;
		ret.L2.EthType = frame.VlanEthType;
		vlanTCI.emplace(frame.VlanTCI);
	}
	switch(ntohs(ret.L2.EthType)) {
	case 0x8892:
		memcpy(&ret.Payload, &frame.Payload.Profinet, sizeof(CapturePayload::Profinet));
		break;
	default:
		//TODO: Support more ethtypes
		break;
	}
	return std::make_pair(ret, vlanTCI);
}

struct HashFrame {
	size_t operator()(const CaptureFrame& frame) const noexcept {
		auto dissected = dissect_frame(frame);
		//XXX: VlanTCI is ignored
		return std::hash<std::string_view>{}(std::string_view(
			(char*)&dissected.first, sizeof(dissected.first)));
	}
};

struct EqualFrame {
	bool operator()(const CaptureFrame& lhs, const CaptureFrame& rhs) const {
		auto lhs_dissected = dissect_frame(lhs);
		auto rhs_dissected = dissect_frame(rhs);
		//XXX: VlanTCi is ignored
		static_assert(sizeof(lhs_dissected.first) == sizeof(CaptureFrameDissected),
			      "check memcmp size in EqualFrame");
		return !memcmp(&lhs_dissected.first, &rhs_dissected.first,
			       sizeof(CaptureFrameDissected));
	}
};

struct CaptureLog {
	std::unordered_set<CaptureFrame, HashFrame, EqualFrame> Frames;
	std::multimap<uint64_t, decltype(Frames)::iterator> Iterators;
	CaptureLog(uint64_t historysec) : HistNanosec(historysec * 1000 * 1000 * 1000){}
	const uint64_t HistNanosec;
	void remove_frame(decltype(Frames)::iterator i) {
		auto range = Iterators.equal_range(get_frame_time(*i));
		for (; range.first != range.second; ++range.first) {
			// Find the entry that has <time, i>
			if (range.first->second == i)
				break;
		}
		assert(range.first != range.second);
		Iterators.erase(range.first);
		Frames.erase(i);
	}
	void log(const CaptureFrame& frame) {
		assert(Iterators.size() == Frames.size());
		for (auto i = Iterators.begin();
		     !Iterators.empty() && i->first + HistNanosec < get_frame_time(frame);
		     i = Iterators.begin()) {
			// remove the oldest
			fprintf(stderr, "Retiring old unmatched frame: ");
			print_frame(&*i->second, stderr);
			Frames.erase(i->second);
			Iterators.erase(i);
		}
		std::pair<decltype(Frames)::iterator , bool> res;
		for (res = Frames.insert(frame); !res.second;
		     res = Frames.insert(frame)) {
			fprintf(stderr, "Retiring Duplicate frame: ");
			print_frame(&*res.first, stderr);
			remove_frame(res.first);
		}
		Iterators.emplace(get_frame_time(frame), res.first);
	}
	std::optional<CaptureFrame> match(const CaptureFrame& frame) {
		auto i = Frames.find(frame);
		if (i == Frames.end()) {
			return std::nullopt;
		}
		std::optional<CaptureFrame> ret{*i};
		remove_frame(i);
		return ret;
	}
};

static const char *str_historysec = getenv("TS_DIFF_HIST_SEC");
static const size_t historysec = str_historysec ? strtoul(str_historysec, nullptr, 10) : DEFAULT_HIST_SEC;

CaptureLog captures[2] = {{historysec}, {historysec}};

static void print_diff(const CaptureFrame& tx, const CaptureFrame& rx, bool tx_is_rhs) {
	assert(rx.DevTime && rx.UserTime);
	assert((tx.DevTime ^ tx.UserTime) == (tx.DevTime | tx.UserTime));
	printf("diff: %s %" PRIi64 " frame: ", tx_is_rhs ? "RxTx" : "TxRx",
	       (int64_t)get_frame_time(rx) - (int64_t)get_frame_time(tx));
	print_frame_notime(&rx, stdout, false);
}

static void read_capture(int fd, bool rhs) {
	CaptureFrame frame;
	size_t toread = sizeof(frame);
	while (toread) {
		ssize_t rc = read(fd, (char*)(&frame + 1) - toread, toread);
		if (rc <= 0 || (size_t)rc > toread) {
			error(1, errno, "reading from %d failed", fd);
		}
		toread -= rc;
	}
	if (!supported_frame(frame)) {
		fprintf(stderr, "ignoring unsupported ");
		print_frame(&frame, stderr);
		return;
	}
	// Sanity check the timestamps
	if ((frame.UserTime ^ frame.DevTime) & 1)
		error(1, 0, "UserTime/DevTime tx/rx mismatch");
	std::optional<CaptureFrame> matched = captures[!rhs].match(frame);
	if (!matched){
		captures[rhs].log(frame);
		return;
	}
	if (is_tx_frame(frame) && is_tx_frame(*matched)) {
		fprintf(stderr, "Both frames are TX !!\n");
		fprintf(stderr, "LHS: ");
		print_frame(rhs ? &*matched : &frame, stderr);
		print_frame(rhs ? &frame : &*matched, stderr);
		exit(1);
	}
	if (is_tx_frame(frame)) {
		print_diff(frame, *matched, rhs);
	} else if (is_tx_frame(*matched)) {
		print_diff(*matched, frame, !rhs);
	} else {
		print_diff(rhs ? *matched : frame,
			   rhs ? frame : *matched,
			   false);
	}
}

static void runloop(int lhs, int rhs) {
	static const int errcond = POLLERR | POLLHUP | POLLNVAL;
	for(;;) {
		pollfd fds[2] = {
			{lhs, POLLIN},
			{rhs, POLLIN},
		};
		int rc = poll(fds, sizeof(fds) / sizeof(fds[0]), -1);
		if (rc < 0) {
			error(1, errno, "poll failed");
		}
		if (fds[0].revents & errcond) {
			error(1, 0, "err condition on lhs: %x", fds[0].revents);
		}
		if (fds[1].revents & errcond) {
			error(1, 0, "err condition on rhs: %x", fds[1].revents);
		}
		if (fds[0].revents & POLLIN) {
			read_capture(lhs, false);
		}
		if (fds[1].revents & POLLIN) {
			read_capture(rhs, true);
		}
	}
}

int main(int argc, char **argv) {
	int lhs, rhs;
	if (argc < 3) {
		lhs = 3;
		rhs = 4;
	} else {
		lhs = atoi(argv[1]);
		rhs = atoi(argv[2]);
	}
	if (!lhs || !rhs) {
		error(1, 0, "invalid file descriptors");
	}
	//run_type = argv[1];
	runloop(lhs, rhs);
	return 0;
}