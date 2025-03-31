#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <error.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cinttypes>
#include <sys/shm.h>
#include <sys/mman.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "capture.h"

int main(int argc, char **argv) {
	if (argc < 2)
		error(1, 0, "buffer tag needs to be specified");
	key_t tag = 0;
	memcpy(&tag, argv[1], std::min(sizeof(tag), strlen(argv[1])));
	int h_ctrl = shmget(tag, 0, 0);
	if (h_ctrl < 0)
		error(1, errno, "failed to get shm for ctrl");
	int h_buff = shmget(tag ^ 1, 0, 0);
	if (h_buff < 0)
		error(1, errno, "failed to get shm for buffer");
	void *mapped_ctrl = shmat(h_ctrl, NULL, SHM_RDONLY);
	if (mapped_ctrl == MAP_FAILED)
		error(1, errno, "failed to map shm for control");
	void *mapped_buff = shmat(h_buff, NULL, SHM_RDONLY);
	if (mapped_buff == MAP_FAILED)
		error(1, errno, "failed to map shm for buffer");
	CaptureReader reader((CaptureBufferCtrl*)mapped_ctrl, (CaptureFrame*)mapped_buff);
	bool decode = !!getenv("TS_DUMP_DECODE");
	for(;;) {
		std::optional<CaptureFrame> frame = reader.drain();
		if (!frame) {
			usleep(10000);
			continue;
		}
		if (!decode) {
			ssize_t rc = write(1, &frame.value(), sizeof(CaptureFrame));
			if (rc != sizeof(CaptureFrame))
				return 0;
			continue;
		}
		print_frame(&*frame, stdout);
	}
}