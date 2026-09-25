#include "preflate.h"

#include <stdint.h>
#include <string.h>
#include <vector>

extern "C" int32_t xt2png_preflate(const uint8_t *raw, int32_t raw_len,
                                   const uint8_t *diff, int32_t diff_len,
                                   uint8_t *out, int32_t out_cap) {
	if (raw == 0 || out == 0 || raw_len < 0 || diff_len < 0 || out_cap <= 0) {
		return 0;
	}
	std::vector<unsigned char> unpacked(raw, raw + raw_len);
	std::vector<unsigned char> recon;
	if (diff != 0 && diff_len > 0) {
		recon.assign(diff, diff + diff_len);
	}
	std::vector<unsigned char> deflate;
	if (!preflate_reencode(deflate, recon, unpacked)) {
		return -1;
	}
	if ((int32_t)deflate.size() > out_cap || deflate.size() > 0x7fffffff) {
		return -2;
	}
	if (!deflate.empty()) {
		memcpy(out, deflate.data(), deflate.size());
	}
	return (int32_t)deflate.size();
}
