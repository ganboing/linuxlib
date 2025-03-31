#include <cinttypes>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "capture.h"

CaptureSession::CaptureSession(CaptureBufferCtrl *_ctrl, CaptureFrame *_buff, size_t n)
 : ctrl(_ctrl), frames(_buff)
{
	ctrl->Total = n;
	ctrl->Current.store(0, std::memory_order::memory_order_relaxed);
	ctrl->Reserved.store(0, std::memory_order::memory_order_relaxed);
}

CaptureFrame *CaptureSession::reserve() {
	uint32_t pos = ctrl->Reserved.fetch_add(1, std::memory_order::memory_order_relaxed);
	return frames + pos % ctrl->Total;
}

void CaptureSession::commit(CaptureFrame* f) {
	uint32_t pos = f - frames, expected = pos;
	uint32_t next = (pos + 1) % ctrl->Total;
	while(!ctrl->Current.compare_exchange_strong(expected, next, std::memory_order::memory_order_release)) {
	     expected = pos;
	}
}

CaptureReader::CaptureReader(const CaptureBufferCtrl *_ctrl, const CaptureFrame *_buff)
 : ctrl(_ctrl), frames(_buff)
{
	pos = ctrl->Current.load(std::memory_order::memory_order_acquire);
}

std::optional<CaptureFrame> CaptureReader::drain()
{
	if (pos == ctrl->Current.load(std::memory_order::memory_order_acquire))
	     return std::nullopt;
	std::optional<CaptureFrame> ret;
	ret.emplace(frames[pos++]);
	pos %= ctrl->Total;
	return ret;
}

void print_frame_notime(const CaptureFrame* frame, FILE* fp, bool prefix, bool newline) {
	fprintf(fp, "%s size=%" PRIu16
		    " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx ->"
		    " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx ethtype=%" PRIx16 " vlanTCI=%" PRIx16 " vlanEthtype=%" PRIx16 "",
		prefix ? "frame: " : "", frame->Size,
		frame->L2.SrcMAC[0], frame->L2.SrcMAC[1], frame->L2.SrcMAC[2], frame->L2.SrcMAC[3], frame->L2.SrcMAC[4], frame->L2.SrcMAC[5],
		frame->L2.DestMAC[0], frame->L2.DestMAC[1], frame->L2.DestMAC[2], frame->L2.DestMAC[3], frame->L2.DestMAC[4], frame->L2.DestMAC[5],
		ntohs(frame->L2.EthType), ntohs(frame->VlanTCI), ntohs(frame->VlanEthType));
	if (ntohs(frame->L2.EthType) == 0x8892 ||
	    (ntohs(frame->L2.EthType) == ETHERTYPE_VLAN && ntohs(frame->VlanEthType) == 0x8892)) {
	     fprintf(fp, " PROFINET frame=%" PRIx16 " cycle=%" PRIu16 " dataStatus=%" PRIu8 " xferStatus=%" PRIu8 "%s",
		     ntohs(frame->Payload.Profinet.FrameID),
		     ntohs(frame->Payload.Profinet.Ctrl.CycleCounter),
		     frame->Payload.Profinet.Ctrl.DataStatus, frame->Payload.Profinet.Ctrl.TransferStatus,
		     newline ? "\n" : "");
	} else {
	     fprintf(fp, "%s", newline ? "\n" : "");
	}
}

void print_frame(const CaptureFrame* frame, FILE* fp, bool newline) {
	fprintf(fp, "frame: userTime=%" PRIu64 " devTime=%" PRIu64 "",
		frame->UserTime, frame->DevTime);
	print_frame_notime(frame, fp, false, newline);
}