#include "xdelta3.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern uint32_t host_pread(uint32_t id, uint32_t pos_lo, uint32_t pos_hi, uint8_t* buf, uint32_t n);
extern uint32_t host_pwrite(uint32_t id, uint32_t pos_lo, uint32_t pos_hi, const uint8_t* buf, uint32_t n);
extern uint32_t host_size_lo(uint32_t id);
extern uint32_t host_size_hi(uint32_t id);

enum { SRC_ID = 0, DIFF_ID = 1, OUT_ID = 2, BLKSIZE = 1u << 20 };

static uint64_t host_size(uint32_t id) {
	return ((uint64_t)host_size_hi(id) << 32) | host_size_lo(id);
}

static uint32_t read_at(uint32_t id, uint64_t pos, uint8_t* buf, uint32_t n) {
	uint32_t got = 0;
	while (got < n) {
		uint32_t k = host_pread(id, (uint32_t)(pos + got), (uint32_t)((pos + got) >> 32), buf + got, n - got);
		if (k == 0) {
			break;
		}
		got += k;
	}
	return got;
}

static uint8_t* srcblk;

static int getblk(xd3_stream* stream, xd3_source* source, xoff_t blkno) {
	uint64_t pos = (uint64_t)blkno * source->blksize;
	uint64_t sz = host_size(SRC_ID);
	uint32_t n = source->blksize;
	(void)stream;
	if (pos >= sz) {
		source->onblk = 0;
		source->curblk = srcblk;
		source->curblkno = blkno;
		return 0;
	}
	if (pos + n > sz) {
		n = (uint32_t)(sz - pos);
	}
	source->onblk = read_at(SRC_ID, pos, srcblk, n);
	source->curblk = srcblk;
	source->curblkno = blkno;
	return 0;
}

uint32_t xdelta_apply_stream(void) {
	xd3_stream stream;
	xd3_config config;
	xd3_source source;
	uint8_t* inbuf = 0;
	uint64_t diff_pos = 0;
	uint64_t diff_size = host_size(DIFF_ID);
	uint64_t out_pos = 0;
	uint32_t ok = 0;
	int ret;
	int source_set = 0;

	memset(&stream, 0, sizeof(stream));
	memset(&config, 0, sizeof(config));
	memset(&source, 0, sizeof(source));
	xd3_init_config(&config, 0);
	config.winsize = BLKSIZE;
	config.getblk = getblk;
	if (xd3_config_stream(&stream, &config) != 0) {
		return 0;
	}
	srcblk = (uint8_t*)malloc(BLKSIZE);
	inbuf = (uint8_t*)malloc(BLKSIZE);
	if (!srcblk || !inbuf) {
		goto done;
	}
	source.blksize = BLKSIZE;
	source.curblk = srcblk;
	source.onblk = 0;
	source.curblkno = (xoff_t)-1;
	source.max_winsize = BLKSIZE;

	for (;;) {
		if (stream.avail_in == 0) {
			uint32_t n = BLKSIZE;
			if (diff_pos >= diff_size) {
				stream.flags |= XD3_FLUSH;
				xd3_avail_input(&stream, inbuf, 0);
			} else {
				if (diff_pos + n > diff_size) {
					n = (uint32_t)(diff_size - diff_pos);
				}
				n = read_at(DIFF_ID, diff_pos, inbuf, n);
				xd3_avail_input(&stream, inbuf, n);
				diff_pos += n;
				if (n == 0) {
					stream.flags |= XD3_FLUSH;
				}
			}
		}
		ret = xd3_decode_input(&stream);
		switch (ret) {
		case XD3_INPUT:
			if (diff_pos >= diff_size) {
				goto finish;
			}
			continue;
		case XD3_GOTHEADER:
			if (!source_set && host_size(SRC_ID) > 0) {
				if (xd3_set_source_and_size(&stream, &source, (xoff_t)host_size(SRC_ID)) != 0) {
					goto done;
				}
				source_set = 1;
			}
			goto again;
		case XD3_WINSTART:
		case XD3_WINFINISH:
			goto again;
		case XD3_OUTPUT:
			if (host_pwrite(OUT_ID, (uint32_t)out_pos, (uint32_t)(out_pos >> 32),
					stream.next_out, stream.avail_out) != stream.avail_out) {
				goto done;
			}
			out_pos += stream.avail_out;
			xd3_consume_output(&stream);
			goto again;
		default:
			goto done;
		}
	again:
		continue;
	}
finish:
	if (xd3_close_stream(&stream) != 0) {
		goto done;
	}
	ok = 1;
done:
	xd3_free_stream(&stream);
	free(inbuf);
	free(srcblk);
	srcblk = 0;
	return ok;
}
