#ifndef MY_NET_CAPTURE_H
#define MY_NET_CAPTURE_H

#include <cstdlib>
#include <cstdint>
#include <atomic>
#include <cstdio>
#include <optional>

struct L2Header {
	uint8_t DestMAC[6];
	uint8_t SrcMAC[6];
	uint16_t EthType;
	uint8_t L2Payload[0];
};
static_assert(sizeof(L2Header) == 14, "check L2Header size");

struct L2VlanHeader {
	L2Header L2;
	uint16_t VlanTCI;
	uint16_t EthTypeV;
	uint8_t L2PayloadV[0];
};
static_assert(sizeof(L2VlanHeader) == 18, "check L2VlanHeader size");

struct ProfinetCtrl {
	uint16_t CycleCounter;
	uint8_t DataStatus;
	uint8_t TransferStatus;
};

union CapturePayload {
	struct {
		uint16_t FrameID;
		ProfinetCtrl Ctrl;
	} Profinet;
};

struct CaptureFrame {
	uint64_t UserTime;
	uint64_t DevTime;
	uint16_t Size;
	// following members are in network endianness
	L2Header L2;
	uint16_t VlanTCI;
	uint16_t VlanEthType;
	CapturePayload Payload;
	uint8_t __unused[22];
};

struct CaptureFrameDissected {
	uint16_t Size;
	L2Header L2;
	CapturePayload Payload;
};

static_assert(sizeof(CaptureFrame) == 64, "check sizeof(CaptureFrame)");

struct CaptureBufferCtrl {
	uint32_t Total;
	char __unused1[64 - sizeof(Total)];
	std::atomic<uint32_t> Current;
	char __unused2[64 - sizeof(Current)];
	std::atomic<uint32_t> Reserved;
	char __unused3[64 - sizeof(Reserved)];
};

struct CaptureSession {
	CaptureSession(CaptureBufferCtrl *_ctrl, CaptureFrame *_buff, size_t n);
	CaptureBufferCtrl* const ctrl;
	CaptureFrame* const frames;
	CaptureFrame *reserve();
	void commit(CaptureFrame*);
};

struct CaptureReader {
	CaptureReader(const CaptureBufferCtrl *_ctrl, const CaptureFrame *_buff);
	std::optional<CaptureFrame> drain();
	const CaptureBufferCtrl* const ctrl;
	const CaptureFrame* const frames;
	uint32_t pos;
};
void print_frame_notime(const CaptureFrame* frame, FILE* fp, bool prefix=true, bool newline=true);
void print_frame(const CaptureFrame* frame, FILE* fp, bool newline=true);

#endif
