#include "LzmaEnc.h"
#include "Alloc.h"
#include <stdint.h>

uint32_t sevenz_lzma(const Byte* src, uint32_t size, const uint32_t* config,
                     uint32_t config_size, Byte* out, uint32_t capacity) {
    if (capacity < 13 || (config_size != 20 && config_size != 36 && config_size != 40) || config[0] < 12 || config[0] > 29) return 0;
    CLzmaEncProps props;
    LzmaEncProps_Init(&props);
    props.dictSize = 1u << config[0];
    props.fb = (int)config[1];
    props.lc = (int)config[2];
    props.lp = (int)config[3];
    props.pb = (int)config[4];
    props.algo = 1;
    props.btMode = 1;
    props.numHashBytes = 4;
    props.numThreads = 1;
    if (config_size >= 32) {
        props.algo = (int)config[5];
        props.btMode = (int)config[6];
        props.numHashBytes = (int)config[7];
    }
    if (config_size >= 40 && config[8] != 0) {
        props.reduceSize = config[8];
    } else if (config_size >= 36) {
        props.reduceSize = size;
    }
    SizeT out_size = capacity - 13, prop_size = 5;
    if (LzmaEncode(out + 13, &out_size, src, size, &props, out, &prop_size, 0, 0, &g_Alloc, &g_Alloc) != SZ_OK) {
        return 0;
    }
    for (unsigned i = 0; i < 8; i++) out[5 + i] = (Byte)((uint64_t)size >> (8 * i));
    return (uint32_t)out_size + 13;
}
