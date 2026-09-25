#define TORNADO_LIBRARY

extern "C" int compress_all_at_once = 0;

#include "../../../third_party/freearc/Compression/Tornado/Tornado.cpp"

#include <stdint.h>
#include <string.h>

struct Buf {
	const uint8_t *in;
	int in_len;
	int in_off;
	uint8_t *out;
	int out_cap;
	int out_off;
};

static int cb(const char *what, void *data, int size, void *aux) {
	Buf *b = (Buf *)aux;
	if (what == 0) {
		return 0;
	}
	if (strcmp(what, "read") == 0) {
		int n = size;
		if (n > b->in_len - b->in_off) {
			n = b->in_len - b->in_off;
		}
		if (n > 0 && data != 0) {
			memcpy(data, b->in + b->in_off, (size_t)n);
		}
		b->in_off += n;
		return n;
	}
	if (strcmp(what, "write") == 0) {
		if (b->out_off + size > b->out_cap) {
			return 0;
		}
		if (size > 0 && data != 0) {
			memcpy(b->out + b->out_off, data, (size_t)size);
		}
		b->out_off += size;
		return size;
	}
	return 0;
}

extern "C" int32_t tor_decode(const uint8_t *in, int32_t in_len, uint8_t *out, int32_t out_cap) {
	if (in == 0 || out == 0 || in_len < 0 || out_cap <= 0) {
		return 0;
	}
	Buf b;
	b.in = in;
	b.in_len = in_len;
	b.in_off = 0;
	b.out = out;
	b.out_cap = out_cap;
	b.out_off = 0;
	int rc = tor_decompress(cb, &b, 0, -1);
	if (rc < 0 || b.out_off <= 0) {
		return 0;
	}
	return (int32_t)b.out_off;
}
