#include "patch.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Host file I/O. id 0=old, 1=diff, 2=new.
extern uint32_t host_pread(uint32_t id, uint32_t pos_lo, uint32_t pos_hi, uint8_t* buf, uint32_t n);
extern uint32_t host_pwrite(uint32_t id, uint32_t pos_lo, uint32_t pos_hi, const uint8_t* buf, uint32_t n);
extern uint32_t host_size_lo(uint32_t id);
extern uint32_t host_size_hi(uint32_t id);

typedef struct {
    uint32_t id;
} host_file;

static uint64_t host_size(uint32_t id) {
    return ((uint64_t)host_size_hi(id) << 32) | host_size_lo(id);
}

static hpatch_BOOL file_input_read(const hpatch_TStreamInput* stream, hpatch_StreamPos_t pos,
                                   unsigned char* data, unsigned char* end) {
    host_file* f = (host_file*)stream->streamImport;
    uint32_t n = (uint32_t)(end - data);
    return host_pread(f->id, (uint32_t)pos, (uint32_t)(pos >> 32), data, n) == n;
}

static hpatch_BOOL file_output_write(const hpatch_TStreamOutput* stream, hpatch_StreamPos_t pos,
                                     const unsigned char* data, const unsigned char* end) {
    host_file* f = (host_file*)stream->streamImport;
    uint32_t n = (uint32_t)(end - data);
    return host_pwrite(f->id, (uint32_t)pos, (uint32_t)(pos >> 32), data, n) == n;
}

// hpatch_sf20 applies an uncompressed HDIFFSF20 stream via host files 0/1/2.
// cache_bytes is the I/O cache on top of stepMemSize; 0 selects 64MiB.
uint32_t hpatch_sf20(uint32_t cache_bytes) {
    host_file old_f = {0}, diff_f = {1}, out_f = {2};
    hpatch_TStreamInput old_s, diff_s;
    hpatch_TStreamOutput out_s;
    hpatch_singleCompressedDiffInfo info;
    unsigned char* cache = 0;
    uint32_t ok = 0;
    size_t io_cache;

    memset(&old_s, 0, sizeof(old_s));
    old_s.streamImport = &old_f;
    old_s.streamSize = host_size(0);
    old_s.read = file_input_read;
    memset(&diff_s, 0, sizeof(diff_s));
    diff_s.streamImport = &diff_f;
    diff_s.streamSize = host_size(1);
    diff_s.read = file_input_read;

    if (!getSingleCompressedDiffInfo(&info, &diff_s, 0)) goto done;
    if (info.oldDataSize != old_s.streamSize || info.compressedSize != 0) goto done;

    memset(&out_s, 0, sizeof(out_s));
    out_s.streamImport = &out_f;
    out_s.streamSize = info.newDataSize;
    out_s.write = file_output_write;

    io_cache = cache_bytes ? cache_bytes : (64u << 20);
    if (io_cache < hpatch_kStreamCacheSize * 3) io_cache = hpatch_kStreamCacheSize * 3;
    cache = (unsigned char*)malloc(info.stepMemSize + io_cache);
    if (!cache) goto done;

    if (!patch_single_compressed_diff(&out_s, &old_s, &diff_s, info.diffDataPos,
                                      info.uncompressedSize, info.compressedSize, 0,
                                      info.coverCount, (hpatch_size_t)info.stepMemSize,
                                      cache, cache + info.stepMemSize + io_cache, 0))
        goto done;
    ok = 1;
done:
    free(cache);
    return ok;
}
