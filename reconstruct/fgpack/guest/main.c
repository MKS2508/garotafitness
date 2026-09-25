#include "LzmaEnc.h"
#include "Alloc.h"
#include <stdint.h>

// Parameters come from the installer recipe; the console defaults to bt4/algo1.
uint32_t fgpack_encode(const Byte* src, uint32_t size, const uint32_t* config,
                      uint32_t config_size, Byte* out, uint32_t capacity) {
    if (capacity < 13 || (config_size != 20 && config_size != 36) || config[0] < 12 || config[0] > 29) return 0;
    CLzmaEncProps props;
    LzmaEncProps_Init(&props);
    props.dictSize = 1u << config[0];
    props.fb = config[1];
    props.lc = config[2]; props.lp = config[3]; props.pb = config[4];
    props.algo = 1; props.btMode = 1; props.numHashBytes = 4;
    props.numThreads = 1;
    if (config_size >= 32) {
        props.algo = (int)config[5];
        props.btMode = (int)config[6];
        props.numHashBytes = (int)config[7];
    }
    if (config_size >= 36) {
        props.reduceSize = size;
    }
    SizeT out_size = capacity - 13, prop_size = 5;
    SRes res = LzmaEncode(out + 13, &out_size, src, size, &props,
                         out, &prop_size, 0, 0, &g_Alloc, &g_Alloc);
    if (res != SZ_OK) return 0;
    for (unsigned i = 0; i < 8; i++) out[5+i] = (Byte)((uint64_t)size >> (8*i));
    return (uint32_t)out_size + 13;
}
