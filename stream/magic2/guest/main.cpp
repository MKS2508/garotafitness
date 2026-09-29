// Reconstructed lolz v22c4b kernel (cls-magic2 is PE-only; INV-03).
// Same guest shape as srep: C++ in, Go NewReader + wazero out.

#include <stdint.h>
#include <string.h>
#ifdef HOST_DEBUG
#include <stdio.h>
#include <stdlib.h>
#ifndef HOST_QUIET
#define TRACE_TOK 1
#endif
#endif

static const uint32_t kL = 1u << 23;
static const uint32_t kMN = 1u << 15;
static const uint32_t kMB = 1u << 14;
static const int kWant = 430889;
static const int kEmu = 2895;
static const int kApp = 6;
static const uint32_t kAppCRC = 0xf75982bb;
// One decodeOpt @ 0x14003afc0 on fg-06: scale-15 bit + 16-sym, then 0xb48.
// PE: p0=0x4000 idx=0, CDF i*0x800, LE state 0x20, renorm 02 00 25 → off=7.
static const int kOptSkip = 7;

static const uint16_t kNibbleTgt[16][16] = {
    {0x0000, 0x8007, 0x800f, 0x8017, 0x801f, 0x8027, 0x802f, 0x8037, 0x803f, 0x8047, 0x804f, 0x8057, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x800f, 0x8017, 0x801f, 0x8027, 0x802f, 0x8037, 0x803f, 0x8047, 0x804f, 0x8057, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x8017, 0x801f, 0x8027, 0x802f, 0x8037, 0x803f, 0x8047, 0x804f, 0x8057, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x801f, 0x8027, 0x802f, 0x8037, 0x803f, 0x8047, 0x804f, 0x8057, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x8027, 0x802f, 0x8037, 0x803f, 0x8047, 0x804f, 0x8057, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x802f, 0x8037, 0x803f, 0x8047, 0x804f, 0x8057, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x8037, 0x803f, 0x8047, 0x804f, 0x8057, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038, 0x803f, 0x8047, 0x804f, 0x8057, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038, 0x0040, 0x8047, 0x804f, 0x8057, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038, 0x0040, 0x0048, 0x804f, 0x8057, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038, 0x0040, 0x0048, 0x0050, 0x8057, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038, 0x0040, 0x0048, 0x0050, 0x0058, 0x805f, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038, 0x0040, 0x0048, 0x0050, 0x0058, 0x0060, 0x8067, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038, 0x0040, 0x0048, 0x0050, 0x0058, 0x0060, 0x0068, 0x806f, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038, 0x0040, 0x0048, 0x0050, 0x0058, 0x0060, 0x0068, 0x0070, 0x8077},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038, 0x0040, 0x0048, 0x0050, 0x0058, 0x0060, 0x0068, 0x0070, 0x0078},
};

static const uint16_t kNibble9Tgt[9][16] = {
    {0x0000, 0x8006, 0x800d, 0x8014, 0x801b, 0x8022, 0x8029, 0x8030, 0x8037, 0x8000, 0, 0, 0, 0, 0, 0},
    {0x0000, 0x0007, 0x800d, 0x8014, 0x801b, 0x8022, 0x8029, 0x8030, 0x8037, 0x8000, 0, 0, 0, 0, 0, 0},
    {0x0000, 0x0007, 0x000e, 0x8014, 0x801b, 0x8022, 0x8029, 0x8030, 0x8037, 0x8000, 0, 0, 0, 0, 0, 0},
    {0x0000, 0x0007, 0x000e, 0x0015, 0x801b, 0x8022, 0x8029, 0x8030, 0x8037, 0x8000, 0, 0, 0, 0, 0, 0},
    {0x0000, 0x0007, 0x000e, 0x0015, 0x001c, 0x8022, 0x8029, 0x8030, 0x8037, 0x8000, 0, 0, 0, 0, 0, 0},
    {0x0000, 0x0007, 0x000e, 0x0015, 0x001c, 0x0023, 0x8029, 0x8030, 0x8037, 0x8000, 0, 0, 0, 0, 0, 0},
    {0x0000, 0x0007, 0x000e, 0x0015, 0x001c, 0x0023, 0x002a, 0x8030, 0x8037, 0x8000, 0, 0, 0, 0, 0, 0},
    {0x0000, 0x0007, 0x000e, 0x0015, 0x001c, 0x0023, 0x002a, 0x0031, 0x8037, 0x8000, 0, 0, 0, 0, 0, 0},
    {0x0000, 0x0007, 0x000e, 0x0015, 0x001c, 0x0023, 0x002a, 0x0031, 0x0038, 0x8000, 0, 0, 0, 0, 0, 0},
};

static const uint16_t kMatchTgt[16][16] = {
    {0x0000, 0x8003, 0x8007, 0x800b, 0x800f, 0x8013, 0x8017, 0x801b, 0x801f, 0x8023, 0x8027, 0x802b, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x8007, 0x800b, 0x800f, 0x8013, 0x8017, 0x801b, 0x801f, 0x8023, 0x8027, 0x802b, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x800b, 0x800f, 0x8013, 0x8017, 0x801b, 0x801f, 0x8023, 0x8027, 0x802b, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x800f, 0x8013, 0x8017, 0x801b, 0x801f, 0x8023, 0x8027, 0x802b, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x8013, 0x8017, 0x801b, 0x801f, 0x8023, 0x8027, 0x802b, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x0014, 0x8017, 0x801b, 0x801f, 0x8023, 0x8027, 0x802b, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x0014, 0x0018, 0x801b, 0x801f, 0x8023, 0x8027, 0x802b, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x0014, 0x0018, 0x001c, 0x801f, 0x8023, 0x8027, 0x802b, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x0014, 0x0018, 0x001c, 0x0020, 0x8023, 0x8027, 0x802b, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x0014, 0x0018, 0x001c, 0x0020, 0x0024, 0x8027, 0x802b, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x0014, 0x0018, 0x001c, 0x0020, 0x0024, 0x0028, 0x802b, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x0014, 0x0018, 0x001c, 0x0020, 0x0024, 0x0028, 0x002c, 0x802f, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x0014, 0x0018, 0x001c, 0x0020, 0x0024, 0x0028, 0x002c, 0x0030, 0x8033, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x0014, 0x0018, 0x001c, 0x0020, 0x0024, 0x0028, 0x002c, 0x0030, 0x0034, 0x8037, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x0014, 0x0018, 0x001c, 0x0020, 0x0024, 0x0028, 0x002c, 0x0030, 0x0034, 0x0038, 0x803b},
    {0x0000, 0x0004, 0x0008, 0x000c, 0x0010, 0x0014, 0x0018, 0x001c, 0x0020, 0x0024, 0x0028, 0x002c, 0x0030, 0x0034, 0x0038, 0x003c},
};

static const uint16_t kSym8Tgt[7][8] = {
    {0x0000, 0x8008, 0x8011, 0x801a, 0x8023, 0x802c, 0x8035, 0x8000},
    {0x0000, 0x0009, 0x8011, 0x801a, 0x8023, 0x802c, 0x8035, 0x8000},
    {0x0000, 0x0009, 0x0012, 0x801a, 0x8023, 0x802c, 0x8035, 0x8000},
    {0x0000, 0x0009, 0x0012, 0x001b, 0x8023, 0x802c, 0x8035, 0x8000},
    {0x0000, 0x0009, 0x0012, 0x001b, 0x0024, 0x802c, 0x8035, 0x8000},
    {0x0000, 0x0009, 0x0012, 0x001b, 0x0024, 0x002d, 0x8035, 0x8000},
    {0x0000, 0x0009, 0x0012, 0x001b, 0x0024, 0x002d, 0x0036, 0x8000},
};

static const int kA690[7] = {0, 1, 2, 3, 17, 18, 0};
// VA 0x14000a697. cls10: edx = table[sym] after the +0x364ca 16-sym.
static const int kA697[16] = {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 20, 21};

// VA 0x1400011a0. cls1 first 8-sym adapt (psraw $6) at 0x14003a24d.
static const uint16_t kOff8Tgt[8][8] = {
    {0x0000, 0x8007, 0x800f, 0x8017, 0x801f, 0x8027, 0x802f, 0x8037},
    {0x0000, 0x0008, 0x800f, 0x8017, 0x801f, 0x8027, 0x802f, 0x8037},
    {0x0000, 0x0008, 0x0010, 0x8017, 0x801f, 0x8027, 0x802f, 0x8037},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x801f, 0x8027, 0x802f, 0x8037},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x8027, 0x802f, 0x8037},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x802f, 0x8037},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x8037},
    {0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038},
};

// VA 0x140002980. Option-header 16-sym adapt (psraw $5) at 0x14003b132.
static const uint16_t kHdrTgt[16][16] = {
    {0x0000, 0x8001, 0x8003, 0x8005, 0x8007, 0x8009, 0x800b, 0x800d, 0x800f, 0x8011, 0x8013, 0x8015, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x8003, 0x8005, 0x8007, 0x8009, 0x800b, 0x800d, 0x800f, 0x8011, 0x8013, 0x8015, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x8005, 0x8007, 0x8009, 0x800b, 0x800d, 0x800f, 0x8011, 0x8013, 0x8015, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x8007, 0x8009, 0x800b, 0x800d, 0x800f, 0x8011, 0x8013, 0x8015, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x8009, 0x800b, 0x800d, 0x800f, 0x8011, 0x8013, 0x8015, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000a, 0x800b, 0x800d, 0x800f, 0x8011, 0x8013, 0x8015, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000a, 0x000c, 0x800d, 0x800f, 0x8011, 0x8013, 0x8015, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000a, 0x000c, 0x000e, 0x800f, 0x8011, 0x8013, 0x8015, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000a, 0x000c, 0x000e, 0x0010, 0x8011, 0x8013, 0x8015, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000a, 0x000c, 0x000e, 0x0010, 0x0012, 0x8013, 0x8015, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000a, 0x000c, 0x000e, 0x0010, 0x0012, 0x0014, 0x8015, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000a, 0x000c, 0x000e, 0x0010, 0x0012, 0x0014, 0x0016, 0x8017, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000a, 0x000c, 0x000e, 0x0010, 0x0012, 0x0014, 0x0016, 0x0018, 0x8019, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000a, 0x000c, 0x000e, 0x0010, 0x0012, 0x0014, 0x0016, 0x0018, 0x001a, 0x801b, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000a, 0x000c, 0x000e, 0x0010, 0x0012, 0x0014, 0x0016, 0x0018, 0x001a, 0x001c, 0x801d},
    {0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000a, 0x000c, 0x000e, 0x0010, 0x0012, 0x0014, 0x0016, 0x0018, 0x001a, 0x001c, 0x001e},
};

// VA 0x14000a6a7 / 0x14000a6b7. 16-sym → option id (0x14003b16e / 0x14003b240).
static const uint8_t kA6A7[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0c, 0x0d, 0x0e, 0x0f, 0x3f, 0x3e, 0x00};
static const uint8_t kA6B7[16] = {0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t kA6C7[16] = {0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00};

// VA 0x140002f20. 8-sym length adapt (psraw $7).
static const uint16_t kLen8Tgt[8][8] = {
    {0x0000, 0x800f, 0x801f, 0x802f, 0x803f, 0x804f, 0x805f, 0x806f},
    {0x0000, 0x0010, 0x801f, 0x802f, 0x803f, 0x804f, 0x805f, 0x806f},
    {0x0000, 0x0010, 0x0020, 0x802f, 0x803f, 0x804f, 0x805f, 0x806f},
    {0x0000, 0x0010, 0x0020, 0x0030, 0x803f, 0x804f, 0x805f, 0x806f},
    {0x0000, 0x0010, 0x0020, 0x0030, 0x0040, 0x804f, 0x805f, 0x806f},
    {0x0000, 0x0010, 0x0020, 0x0030, 0x0040, 0x0050, 0x805f, 0x806f},
    {0x0000, 0x0010, 0x0020, 0x0030, 0x0040, 0x0050, 0x0060, 0x806f},
    {0x0000, 0x0010, 0x0020, 0x0030, 0x0040, 0x0050, 0x0060, 0x0070},
};

// VA 0x140005ac0. Decode init (0x140028b67) sets [obj+0x70] here.
// mixer = table[hist]; hist = 0x5b40[n][pos & pc_mask]. Default n=0
// is all-zero hist, so mixer is always 99 and the second bit is skipped.
// tok==2 is DXT only when mixer <= 8 (jmp table 0xa880); else error.
static const uint8_t kMixTab[80] = {
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 2,
    99, 99, 99, 3, 99, 99, 99, 4, 99, 99, 99, 99, 99, 99, 99, 0, 99, 1, 99, 99, 99, 99, 99, 5, 6, 99, 7, 99, 99, 8, 99, 99,
    99, 9, 99, 99, 99, 10, 11, 12, 13, 0, 0, 0, 0, 0, 0, 0,
};

// VA 0x140005b40. 16-byte rows; n = min([obj+0x64], 0x24). Ctor +0x64 = 0.
static const uint8_t kHistTab[37][16] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x38, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x3a, 0x3b, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x3d, 0x3e, 0x3f, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26},
    {0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x41, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x45, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x46, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x47, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x48, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

// VA 0x140005a98. [obj+0xc39] when n < 0x25 (0x140028c91).
static const uint8_t kPcMask[37] = {
    0, 0, 1, 0, 3, 7, 15, 15, 15, 0, 0, 0, 1, 3, 7, 15,
    0, 1, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    3, 3, 7, 3, 15,
};

// VA 0x14000a260. Literal uses [esi]; class 11/1 +16; class 4-10 +32; class 0 +48.
static const uint8_t kEsiTab[336] = {
    0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 7, 8, 0, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 13, 13, 13, 13, 13, 10,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 14, 14, 14, 14, 14, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 14, 14, 14, 14, 14, 12,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    73, 77, 72, 76, 76, 108, 140, 75, 75, 107, 74, 74, 74, 107, 107, 73, 73, 139, 72, 72, 72, 106, 106, 106, 139, 139, 139, 69, 69, 69, 105, 145,
    77, 112, 145, 177, 76, 177, 177, 177, 75, 177, 111, 74, 74, 144, 73, 73, 73, 110, 110, 110, 72, 144, 144, 71, 109, 70, 70, 109, 109, 143, 143, 143,
    108, 108, 108, 108, 108, 108, 143, 143, 143, 143, 143, 176, 107, 107, 107, 176, 176, 176, 176, 176, 176, 176, 176, 106, 142, 142, 142, 142, 142, 142, 142, 105,
    105, 104, 104, 104, 104, 104, 104, 104, 104, 141, 141, 141, 103, 103, 103, 103, 141, 141, 141, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175,
    175, 175, 175, 140, 140, 140, 140, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 174, 174, 174, 174, 174,
    174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 138, 174, 138, 138, 174, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137,
    173, 173, 136, 173, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 172, 172, 172, 172, 172,
    172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172,
};

static int esi_after_match(int esi, int cls, int hist) {
  // Match classes index the esi map by hist (r13), not the live esi.
  // cls0 0xa290[hist]; cls1 0xa270[hist]; cls4-10/12-15 0xa280[hist].
  (void)esi;
  int i;
  if (cls == 0) i = 48 + (hist & 15);
  else if ((cls >= 4 && cls <= 10) || (cls >= 12 && cls <= 15)) i = 32 + (hist & 15);
  else i = 16 + (hist & 15);
  if (i < 0) i = 0;
  if (i >= 336) i = 335;
  return kEsiTab[i];
}

struct Rans {
  uint32_t x;
  const uint8_t *buf;
  int off, len;
  bool ok;
};

static void renorm(Rans *r) {
  while (r->x < kL) {
    if (r->off >= r->len) {
      r->ok = false;
      return;
    }
    r->x = (r->x << 8) | r->buf[r->off++];
  }
}

static int get_bit(Rans *r, uint16_t *p0, unsigned nbits, unsigned shift) {
  if (!r->ok) return -1;
  uint32_t m = 1u << nbits;
  uint32_t p = *p0;
  if (p >= m && p != 0) p = m - 1;
  uint32_t slot = r->x & (m - 1);
  uint32_t quo = r->x >> nbits;
  if (slot < p) {
    r->x = quo * p + slot;
    *p0 = (uint16_t)(p + ((m - p) >> shift));
    renorm(r);
    return 0;
  }
  r->x = r->x - p * (quo + 1);
  uint32_t np = p - (p >> shift);
  if (np == 0) np = 1;
  *p0 = (uint16_t)np;
  renorm(r);
  return 1;
}

static void adapt16(uint16_t *cdf, int sym, const uint16_t tgt[][16], int shift) {
  if (sym < 0) sym = 0;
  if (sym > 15) sym = 15;
  for (int j = 0; j < 16; j++) {
    int16_t d = (int16_t)tgt[sym][j] - (int16_t)cdf[j];
    cdf[j] = (uint16_t)((int16_t)cdf[j] + (d >> shift));
  }
}

static void adapt8(uint16_t *cdf, int sym, const uint16_t tgt[][8], int shift) {
  if (sym < 0) sym = 0;
  if (sym > 7) sym = 7;
  for (int j = 0; j < 8; j++) {
    int16_t d = (int16_t)tgt[sym][j] - (int16_t)cdf[j];
    cdf[j] = (uint16_t)((int16_t)cdf[j] + (d >> shift));
  }
}

static int find16(const uint16_t *cdf, uint32_t slot, int last) {
  for (int j = 1; j < last; j++) {
    if ((int16_t)cdf[j] > (int16_t)slot) return j;
  }
  return last;
}

// v22 0x14002b8e6: mixed = (w*A + (uint16)(0-w)*B) >> 16  (pmulhuw+paddw)
static void mix_cdf(uint16_t *mixed, const uint16_t *A, const uint16_t *B, uint16_t w) {
  uint16_t nw = (uint16_t)(0u - w);
  for (int i = 0; i < 16; i++) {
    mixed[i] = (uint16_t)((((uint32_t)w * A[i]) >> 16) + (((uint32_t)nw * B[i]) >> 16));
  }
}

static int get_nibble_mix(Rans *r, uint16_t *A, uint16_t *B, uint16_t *wp, int last, int shift,
                          const uint16_t tgt[][16]) {
  if (!r->ok) return -1;
  uint16_t mixed[16];
  uint16_t w = *wp;
  mix_cdf(mixed, A, B, w);
  uint32_t slot = r->x & (kMN - 1);
  uint32_t quo = r->x >> 15;
  int i = find16(mixed, slot, last);
  uint32_t start = mixed[i - 1];
  uint32_t end = (i < 16) ? mixed[i] : 0x8000;
  if (end <= start) end = start + 1;
  r->x = (end - start) * quo + (slot - start);
  int sym = i - 1;
  uint16_t fA, fB;
  if (i < 16) {
    fA = (uint16_t)(A[i] - A[i - 1]);
    fB = (uint16_t)(B[i] - B[i - 1]);
  } else {
    fA = (uint16_t)(0x8000 - A[15]);
    fB = (uint16_t)(0x8000 - B[15]);
  }
  uint16_t w2 = (uint16_t)(w - (w >> 4));
  if (fA >= fB) w2 = (uint16_t)(w2 + 0x0fff);
  *wp = w2;
  adapt16(A, sym, tgt, shift);
  adapt16(B, sym, tgt, shift);
  renorm(r);
  return sym;
}

static int get_nibble(Rans *r, uint16_t *cdf, int last, int shift, const uint16_t tgt[][16]) {
  if (!r->ok) return -1;
  uint32_t slot = r->x & (kMN - 1);
  uint32_t quo = r->x >> 15;
  int i = find16(cdf, slot, last);
  uint32_t start = cdf[i - 1];
  uint32_t end = (i < last && i < 16) ? cdf[i] : 0x8000;
  if (end <= start) end = start + 1;
  r->x = (end - start) * quo + (slot - start);
  int sym = i - 1;
  adapt16(cdf, sym, tgt, shift);
  renorm(r);
  return sym;
}

// 8-sym find: add 0x100+bsf. Length uses >>7/0x2f20; cls1 s0 uses >>6/0x11a0.
static int get_sym8_tgt(Rans *r, uint16_t *cdf, const uint16_t tgt[][8], int shift) {
  if (!r->ok) return -1;
  uint32_t slot = r->x & (kMN - 1);
  uint32_t quo = r->x >> 15;
  int i = find16(cdf, slot, 8);
  uint32_t start = cdf[i - 1];
  uint32_t end = (i < 8) ? cdf[i] : 0x8000;
  if (end <= start) end = start + 1;
  r->x = (end - start) * quo + (slot - start);
  int sym = i - 1;
  adapt8(cdf, sym, tgt, shift);
  renorm(r);
  return sym;
}

static int get_sym8(Rans *r, uint16_t *cdf) { return get_sym8_tgt(r, cdf, kLen8Tgt, 7); }

// 0x14003bb93 builds obj+0xbe0 from 0xa6e7 (8-byte {base56, nbits8}).
// 0x14003bc18 builds obj+0xc00 from 0xa706. decode_int @ 0x140036d93:
// offset = base[s] + extra(nbits[s]), not (1<<s)+extra.
static const uint8_t kA6E7[] = {
    5, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    5, 6, 7, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
};
static const uint8_t kA706[] = {
    0, 0, 0, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    2, 2, 2, 3, 3, 4, 5, 6, 4, 4, 4, 4, 5, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
};
// VA 0x14000a6d7. +0xbc0 ladder, limit 0x1000. 0x140036646.
static const uint8_t kA6D7[] = {3, 3, 3, 3, 3, 4, 4, 4, 5, 5, 6, 7, 8, 9, 10, 11};

static int be0_base(const uint8_t *nb, int ntab, int s) {
  int b = 0;
  if (s > ntab) s = ntab;
  for (int i = 0; i < s; i++) {
    int n = nb[i];
    if (n >= 30) break;
    b += 1 << n;
  }
  return b;
}

static int decode_bc0(Rans *r, uint16_t *cdf8, uint16_t *bits) {
  int s = get_sym8(r, cdf8);
  if (s < 0) return -1;
  if (s > 15) s = 15;
  int nbits = kA6D7[s];
  int d = be0_base(kA6D7, 16, s) + s; // leal -1(%rcx,%rdx) with rcx=bsf=s+1
  if (nbits > 3) {
    int k = nbits - 3;
    uint32_t raw = r->x & ((1u << k) - 1);
    r->x >>= k;
    renorm(r);
    d += (int)(raw * 8);
  }
  (void)bits;
  return d;
}

static int bitlen(uint32_t x);
static void init_nibble(uint16_t *d);

// 0x140036730: cls11 index. 16-sym at min(bitlen(first),7), >>5 / 0x2980,
// escape 15, then +0xba0 {base56,nbits8} + nbits scale-14 bits.
static int decode_cls11_idx(Rans *r, int first, uint16_t *rows, uint16_t *esc, uint16_t *bp) {
  int bl = bitlen((uint32_t)(first < 0 ? 0 : first));
  if (bl > 7) bl = 7;
  int s = get_nibble(r, rows + bl * 16, 16, 5, kHdrTgt);
  if (s < 0) return -1;
  if (s == 15) {
    int sx = get_nibble(r, esc, 16, 5, kHdrTgt);
    if (sx < 0) return -1;
    s = 15 + sx;
  }
  if (s < 0) s = 0;
  if (s > 30) s = 30;
  int nbits = kA6E7[s];
  if (nbits > 24) nbits = 24;
  int d = be0_base(kA6E7, (int)sizeof(kA6E7), s);
  uint32_t extra = 0;
  for (int i = 0; i < nbits; i++) {
    int b = get_bit(r, &bp[s * 16 + i], 14, 5);
    if (b < 0) return -1;
    extra = (extra << 1) | (uint32_t)b;
  }
  return d + (int)extra;
}

// 0x140036b00: mix16 A vs B=A+0x44+bitlen(lookback)*34, then kA6E7 extra bits.
struct IntModel {
  uint16_t A[16];
  uint16_t Brow[16][16];
  uint16_t w;
  uint16_t s2[16][16];
  uint16_t s3[16][16];
  uint16_t bp[16];
};

static void int_model_init(IntModel *M) {
  init_nibble(M->A);
  for (int i = 0; i < 16; i++) {
    init_nibble(M->Brow[i]);
    init_nibble(M->s2[i]);
    init_nibble(M->s3[i]);
    M->bp[i] = kMB / 2;
  }
  M->w = 0x8000;
}

static int decode_int_pe(Rans *r, IntModel *M, int lookback) {
  int bl = lookback == 0 ? 0 : bitlen((uint32_t)lookback);
  if (bl > 15) bl = 15;
  int s = get_nibble_mix(r, M->A, M->Brow[bl], &M->w, 16, 5, kHdrTgt);
  if (s < 0) return -1;
  if (s == 15) {
    int e = get_nibble(r, M->A, 16, 5, kHdrTgt);
    if (e < 0) return -1;
    s = 15 + e;
  }
  if (s < 0) s = 0;
  if (s > 30) s = 30;
  int nbits = kA6E7[s];
  int base = be0_base(kA6E7, (int)sizeof(kA6E7), s);
  if (nbits < 6) {
    int extra = 0;
    for (int i = 0; i < nbits; i++) {
      int b = get_bit(r, &M->bp[s & 15], 14, 4);
      if (b < 0) return -1;
      extra = extra * 2 + b;
    }
    return base + extra;
  }
  int srow = s > 15 ? 15 : s;
  int s2 = get_nibble(r, M->s2[srow], 16, 6, kMatchTgt);
  if (s2 < 0) return -1;
  int sh = nbits >= 9 ? ((nbits + 60) & 63) : 5;
  int raw = 0;
  if (nbits > 9) {
    int rb = (nbits + 23) & 31;
    raw = (int)(r->x & ((1u << rb) - 1));
    r->x >>= rb;
    renorm(r);
    raw <<= 5;
  }
  int s3 = get_nibble(r, M->s3[s2 & 15], 16, 7, kNibbleTgt);
  if (s3 < 0) return -1;
  int b = get_bit(r, &M->bp[srow], 14, 5);
  if (b < 0) return -1;
  return base + (s2 << sh) + raw + 2 * s3 + b;
}

// 0x14006f8ad / in-image clone call 0x14006b781. Same rel32 as cls11's
// 0x14006f513. Mixed 16-sym (A at +0x4a42a, B at +0xe562a), adapt >>5 /
// 0x2980, escape 15 is a plain 16-sym at A+0x22 (decode_int 0x140036cd3).
// Caller only writes the 5th arg (B pointer), not the 6th lookback, so
// this is not the a6e7 nbits tail — return is the symbol, then +10.
static int decode_mix16_esc(Rans *r, uint16_t *A, uint16_t *B, uint16_t *wp, uint16_t *esc) {
  int s = get_nibble_mix(r, A, B, wp, 16, 5, kHdrTgt);
  if (s < 0) return -1;
#ifndef LENESC_NO15
  if (s == 15) {
    int sx = get_nibble(r, esc, 16, 5, kHdrTgt);
    if (sx < 0) return -1;
    s = 15 + sx;
  }
#else
  (void)esc;
#endif
  return s;
}

// cls2 @ 0x14003a0c4 / cls3 @ 0x14003a02a call past the image.
// In-image twin 0x140036b00: mixed 16-sym, adapt >>5 / 0x2980, escape 15.
static int decode_new_off(Rans *r, uint16_t *A, uint16_t *B, uint16_t *wp, uint16_t *esc,
                          uint16_t *bp, const uint8_t *nbtab, int ntab, uint16_t *mid, uint16_t *tail) {
#ifdef TRACE_TOK
  static int nmix;
  if (nmix < 6) {
    fprintf(stderr, "newoff-mix slot=%04x x=%08x w=%04x\n", r->x & 0x7fff, r->x, (unsigned)*wp);
    nmix++;
  }
#endif
  int s = get_nibble_mix(r, A, B, wp, 16, 5, kHdrTgt);
#ifdef TRACE_TOK
  static int npost;
  if (npost < 6) {
    fprintf(stderr, "newoff-s s=%d x=%08x slot=%04x\n", s, r->x, r->x & 0x7fff);
    npost++;
  }
#endif
  if (s < 0) return -1;
  if (s == 15) {
    int sx = get_nibble(r, esc, 16, 5, kHdrTgt);
    if (sx < 0) return -1;
    s = 15 + sx;
#ifdef TRACE_TOK
    if (npost <= 6) fprintf(stderr, "newoff-esc s=%d x=%08x\n", s, r->x);
#endif
  }
  if (s < 0) s = 0;
  if (s >= ntab) s = ntab - 1;
  if (s > 30) s = 30;
  int nbits = nbtab[s];
  if (nbits > 24) nbits = 24;
  int d = be0_base(nbtab, ntab, s);
  if (nbits <= 5) {
    // 0x140036db8: xor esi; jmp 0x14006d0d4. nbits × scale-14, no tail.
    uint32_t extra = 0;
    for (int i = 0; i < nbits; i++) {
      int b = get_bit(r, &bp[s * 16 + i], 14, 5);
      if (b < 0) return -1;
      extra = (extra << 1) | (uint32_t)b;
    }
    d += (int)extra;
#ifdef TRACE_TOK
    static int nrep0;
    if (nrep0 < 8) {
      fprintf(stderr, "newoff5 s=%d nbits=%d d=%d x=%08x\n", s, nbits, d, r->x);
      nrep0++;
    }
#endif
    return d;
  }
  // 0x140036dbf: 16-sym at cdf+s*34+0x4a4, adapt >>6 / 0x1f00.
  int s2 = get_nibble(r, mid + s * 16, 16, 6, kMatchTgt);
  if (s2 < 0) return -1;
#ifdef TRACE_TOK
  static int ns2;
  if (ns2 < 4) {
    fprintf(stderr, "newoff-s2 s2=%d x=%08x slot=%04x\n", s2, r->x, r->x & 0x7fff);
    ns2++;
  }
#endif
  int sh = ((nbits < 9 ? 9 : nbits) + 60) & 63;
  d += s2 << sh;
  if (nbits > 9) {
    int k = nbits - 9;
    uint32_t low = r->x & ((1u << k) - 1);
    r->x >>= k;
    renorm(r);
    d += (int)(low << 5);
  }
  // tail always: s3 at s*34+s2*1088+0x8e4 >>7/0x1c00; bit at s*2+s2*64+0x4ce4.
  int s3 = get_nibble(r, tail + (s * 16 + s2) * 16, 16, 7, kNibbleTgt);
  if (s3 < 0) return -1;
  int bit = get_bit(r, &bp[s * 16 + s2], 14, 5);
  if (bit < 0) return -1;
  d += 2 * s3 + bit;
#ifdef TRACE_TOK
  static int nrep;
  if (nrep < 8) {
    fprintf(stderr, "newoff s=%d nbits=%d s2=%d s3=%d d=%d x=%08x\n", s, nbits, s2, s3, d, r->x);
    nrep++;
  }
#endif
  return d;
}

// ROLZ lists at obj+0xc90 / cursors +0x88 / cap +0xc28.
// Default cap = (opt[+8]<<11)+0x800 → 0x800 when dword[+8]=0.
static const int kRolzCap = 2048;
// 0 = PE ROLZ list, 1 = raw second decode_int as offset, 2 = that+1
static int gCls11Mode = 0;
static uint32_t gRolz[256][2048];
static int gRolzCur[256];
// Bytes of input consumed by the last magic2_decode call (opt_skip + r.off on
// the accepting decode_v22 path). The host reads this between calls so the
// streaming reader can advance r.cur without bisecting.
static int gLastConsumed = 0;

static void rolz_reset(void) {
  memset(gRolz, 0, sizeof(gRolz));
  for (int i = 0; i < 256; i++) gRolzCur[i] = 0;
}

static void rolz_push(int ctx, int pos) {
  ctx &= 255;
  int c = gRolzCur[ctx];
  gRolz[ctx][c] = (uint32_t)pos;
  c++;
  if (c >= kRolzCap) c = 0;
  gRolzCur[ctx] = c;
}

static int rolz_lookup(int ctx, int idx, int n) {
  // PE 0x140039c83: slot = cursor[ctx] + ~idx; if (slot<0) slot += cap.
  ctx &= 255;
  int cur = gRolzCur[ctx];
  if (cur < 1) return 1;
  int slot = cur + ~idx;
  if (slot < 0) slot += kRolzCap;
  if (slot < 0) slot = 0;
  if (slot >= kRolzCap) slot %= kRolzCap;
  int pos = (int)gRolz[ctx][slot];
  int d = n - pos;
  if (d < 1) d = 1;
  return d;
}

static int bitlen(uint32_t x) {
  if (x == 0) return 0;
  int n = 0;
  while (x) {
    x >>= 1;
    n++;
  }
  return n;
}

static uint32_t abs32(int32_t x) { return x < 0 ? (uint32_t)(-x) : (uint32_t)x; }

static uint32_t crc32_ieee(const uint8_t *p, int n) {
  uint32_t c = 0xffffffffu;
  for (int i = 0; i < n; i++) {
    c ^= p[i];
    for (int b = 0; b < 8; b++) c = (c >> 1) ^ (0xedb88320u & (uint32_t)-(int32_t)(c & 1));
  }
  return ~c;
}

static void init_nibble(uint16_t *d) {
  for (int i = 0; i < 16; i++) d[i] = (uint16_t)(i * 0x800);
}

static void init_sym8(uint16_t *d) {
  for (int i = 0; i < 8; i++) d[i] = (uint16_t)(i * 0x1000);
}

struct Hist {
  uint32_t w08, w0c, w10, w14, w18, w1c, w20, w24;
};

static int hist_h1(const Hist *h) {
  return bitlen((uint8_t)abs32((int32_t)h->w20 - (int32_t)h->w24));
}

static int hist_row(const Hist *h) {
  uint32_t a = abs32((int32_t)h->w08 - (int32_t)h->w0c);
  uint32_t b = abs32((int32_t)h->w10 - (int32_t)h->w14);
  int h0 = bitlen((uint8_t)((a + b) >> 1));
  int h1 = hist_h1(h);
  int r = h0 * 9 + h1;
  if (r < 0) return 0;
  if (r >= 81) return 80;
  return r;
}

static void apply_sample(Hist *h, uint32_t n0, uint32_t n1) {
  uint32_t a0 = (abs32((int32_t)n0) | 1);
  uint32_t a1 = (abs32((int32_t)n1) | 1);
  uint32_t m0 = ((a0 + 2 * h->w20) >> 1) & 0xff;
  uint32_t m1 = ((a1 + 2 * h->w24) >> 1) & 0xff;
  h->w08 = h->w10;
  h->w0c = h->w14;
  h->w10 = h->w20;
  h->w14 = h->w24;
  h->w18 = m0;
  h->w1c = m1;
  h->w20 = m0;
  h->w24 = m1;
}

static int extra_sample(Rans *r, Hist *h, uint16_t *bits, int bsf, int h1) {
  if (bsf <= 1) {
    apply_sample(h, 0, 0);
    return 0;
  }
  int sym = bsf - 1;
  if (sym > 8) sym = 8;
  if (h1 < 0) h1 = 0;
  if (h1 > 8) h1 = 8;
  int r10 = 0, r13 = 0, rdx = 0;
  for (int i = 0; i < sym; i++) {
    int off = (h1 << 11) + ((sym - 1) << 8) + i * 32 + 8 * rdx;
    off /= 2;
    int b0 = get_bit(r, &bits[off], 14, 4);
    if (b0 < 0) return -1;
    int b1 = get_bit(r, &bits[off + 1 + b0], 14, 4);
    if (b1 < 0) return -1;
    r10 = r10 * 2 + b0;
    r13 = r13 * 2 + b1;
    rdx = b1 + 2 * b0;
  }
  apply_sample(h, (uint32_t)r10, (uint32_t)r13);
  return r10;
}

// Insert a new distance at reps[17] (obj+0x44). PE: movdqu [+0x44]→[+0x48],
// then movl at +0x44 (cls1 0x14003a356 / x86 cls3 falls into 0x42f710).
static void insert_new_off(int *reps, int nrep, int d) {
  if (nrep > 20) reps[20] = reps[19];
  if (nrep > 19) reps[19] = reps[18];
  if (nrep > 18) reps[18] = reps[17];
  if (nrep > 17) reps[17] = d;
}

// 0x140039dd0: a690[cls-4] is an index into the recent-offset array
// (0..3, 17, 18), not a raw bit count. Rotate that slot to [0].
// cls1/2/3 insert at +0x44 (index 17) and return the new distance.
static int decode_off(int cls, int extra, int *rep0, int *reps, int nrep) {
  if (cls == 0) {
    if (*rep0 < 1) *rep0 = 1;
    return *rep0;
  }
  if ((cls >= 4 && cls <= 10) || (cls >= 12 && cls <= 15)) {
    int idx = extra;
    if (cls >= 12) idx = cls - 12;
    else if (cls != 10) idx = kA690[cls - 4];
    if (idx >= 0 && idx < nrep) {
      int d = reps[idx];
      if (idx > 0) {
        for (int i = idx; i > 0; i--) reps[i] = reps[i - 1];
      }
      if (d < 1) d = 1;
      reps[0] = d;
      *rep0 = d;
      return d;
    }
  }
  // cls 1/2/3/11: insert at +0x44 only. class 0 still reads reps[0].
  // decode_int returns 0 (cls2 testl %ebp,%ebp / je). Do not bump to 1.
  int d = extra;
  if (d < 0) d = 0;
  insert_new_off(reps, nrep, d);
  return d;
}

static int hit_crc(const uint8_t *out, int n) {
  if (n < kEmu + kApp) return 0;
  return crc32_ieee(out + kEmu, kApp) == kAppCRC;
}

static int decode_iir(const uint8_t *src, int slen, uint8_t *dst, int dcap, unsigned bit_adapt) {
  if (slen < 4) return 0;
  Rans r;
  r.buf = src;
  r.off = 4;
  r.len = slen;
  r.ok = true;
  r.x = ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) | ((uint32_t)src[2] << 8) | src[3];
  renorm(&r);
  uint16_t hiGrid[81 * 16];
  uint16_t clsGrid[81 * 16];
  for (int i = 0; i < 81; i++) {
    init_nibble(hiGrid + i * 16);
    init_nibble(clsGrid + i * 16);
  }
  uint16_t hiBits[9 * 2048 / 2];
  for (int i = 0; i < 9 * 1024; i++) hiBits[i] = kMB / 2;
  uint16_t litP = kMB / 2;
  uint16_t lenTab[256 * 8];
  for (int i = 0; i < 256; i++) init_sym8(lenTab + i * 8);
  uint16_t bmTab[64];
  for (int i = 0; i < 64; i++) bmTab[i] = kMB / 2;
  Hist hi = {}, clsH = {};
  int n = 0;
  int prev = 0, rep0 = 1;
  int reps[4] = {1, 1, 1, 1};
  while (n < dcap && n < kWant && r.ok) {
    if (r.x < kL && r.off >= r.len) break;
    int bit = get_bit(&r, &litP, 14, bit_adapt);
    if (bit < 0) break;
    if (bit == 0) {
      int row = hist_row(&hi);
      int bsf;
      int hn = get_nibble(&r, hiGrid + row * 16, 9, 6, kNibble9Tgt);
      if (hn < 0) break;
      bsf = hn + 1;
      int r10 = extra_sample(&r, &hi, hiBits, bsf, hist_h1(&hi));
      if (r10 < 0) break;
      dst[n++] = (uint8_t)r10;
      prev = dst[n - 1];
      continue;
    }
    if (n == 0) break;
    int row = hist_row(&clsH);
    int cls = get_nibble(&r, clsGrid + row * 16, 16, 6, kMatchTgt);
    // PE cmp $0xb / ja: cls 12-15 are MTF reps[cls-12], length 2.
    if (cls < 0 || cls > 15) break;
    apply_sample(&clsH, (uint32_t)(cls & 0xf), 0);
    int extra = 0;
    if (cls != 0) {
      int nb = (cls >= 4 && cls <= 9) ? kA690[cls - 4] : -1;
      if (nb > 0) {
        for (int i = 0; i < nb && i < 18; i++) {
          int b = get_bit(&r, &bmTab[i % 64], 14, 4);
          if (b < 0) return 0;
          extra = extra * 2 + b;
        }
      } else if (cls == 1 || cls == 2 || cls == 3 || cls == 11) {
        int d = get_nibble(&r, hiGrid + hist_row(&hi) * 16, 16, 7, kNibbleTgt);
        if (d < 0) break;
        extra = d + 1;
      }
    }
    decode_off(cls, extra, &rep0, reps, 4);
    int ln = get_nibble(&r, lenTab + (prev % 256) * 8, 8, 6, kNibbleTgt);
    if (ln < 0) break;
    int m = ln + 3;
    if (m == 10) {
      int en = get_nibble(&r, lenTab + (prev % 256) * 8, 8, 6, kNibbleTgt);
      if (en < 0) break;
      m = 10 + en;
    }
    if (m <= 0 || rep0 <= 0 || rep0 > n) break;
    for (int i = 0; i < m && n < dcap && n < kWant; i++) {
      dst[n] = dst[n - rep0];
      prev = dst[n];
      n++;
    }
  }
  return hit_crc(dst, n) ? n : 0;
}

static int ctx_hi(int prev, int rep0lit, int pos) {
  return (prev >> 0) | ((rep0lit >> 4) << 8) | ((pos & 3) << 12);
}

// v20 0x140013a64 / v22 0x14002ba51: if hi == prev>>4 use (prev&0xf)+16 else hi.
static int ctx_lo_pe(int prev, int hi) {
  if (hi == ((prev >> 4) & 0xf)) return (prev & 0xf) + 16;
  return hi;
}

// In-image cousin of past-image 0x140075b29 / 0x140075b60 @ 0x14003b430.
// Model A (init 0x14003edb0): +0x08 ctx, +0x0a ctx, +0x0c p0s (0x4000),
// +0x2c 16-sym CDF stride 0x44, +0x46c escape, +0x8ac bit tree.
// Call is (state*, src**, A, widx=0, nbits=6, flag=1). nbits=6 is the
// hardcoded context mask 0x3f / row stride 128 of this cousin.
// flag=1: always decode the integer (skip the optional presence bit).
// Presence-bit path returns 0 on fg-06 and cannot feed 0x14005fc5d.
static const int kExtraBits = 2048;

struct ExtraModel {
  uint8_t ctx8, ctxa;
  uint16_t p0[16];
  uint16_t cdf[16][16];
  uint16_t esc[16][16];
  uint16_t bits[kExtraBits];
};

static void extra_init(ExtraModel *A) {
  A->ctx8 = 0;
  A->ctxa = 0;
  for (int i = 0; i < 16; i++) {
    A->p0[i] = 0x4000;
    init_nibble(A->cdf[i]);
    init_nibble(A->esc[i]);
  }
  for (int i = 0; i < kExtraBits; i++) A->bits[i] = 0x4000;
}

static int decode_opt_int(Rans *r, ExtraModel *A, int skip_first) {
  if (!skip_first) {
    int idx = A->ctx8 & 15;
    int bit = get_bit(r, &A->p0[idx], 15, 4);
    if (bit < 0) return -1;
    A->ctx8 = (uint8_t)((bit + 2 * A->ctx8) & 3);
    if (bit == 0) return 0;
  }
  int ctx = A->ctxa;
  if (ctx > 15) ctx = 15;
  int s = get_nibble(r, A->cdf[ctx], 16, 5, kHdrTgt);
  if (s < 0) return -1;
  if (s == 15) {
    int sx = get_nibble(r, A->esc[ctx], 16, 5, kHdrTgt);
    if (sx < 0) return -1;
    s = 15 + sx;
  }
  A->ctxa = (uint8_t)(s + 1);
  int eax = 1, rdx = 1;
  for (int i = 0; i < s; i++) {
    int off = s * 64 + rdx;
    if (off < 0) off = 0;
    if (off >= kExtraBits) off = kExtraBits - 1;
    int b = get_bit(r, &A->bits[off], 15, 4);
    if (b < 0) return -1;
    rdx = (b + 2 * rdx) & 0x3f;
    eax = b + 2 * eax;
  }
  return eax;
}

static int gExtraA, gExtraB, gHdrOff;
static ExtraModel gModA, gModB;

// 0x14003afc0 decodeOpt: separate rANS at 0xb40/0xb48, not the LZ 0xb38.
// After kA6A7[s] the common path calls two past-image integers
// (0x140075b29 A=model+0x54, 0x140075b60 A=model+0x1900).
static int decode_opt_header(Rans *r) {
  uint16_t ptab[2] = {0x4000, 0x4000};
  int idx = 0;
  int bit = get_bit(r, &ptab[idx], 15, 5);
  if (bit < 0) return -1;
  idx = bit;
  uint16_t row0[16], row1[16];
  init_nibble(row0);
  init_nibble(row1);
  int s = get_nibble(r, row0, 16, 5, kHdrTgt);
  if (s < 0) return -1;
  int opt = (s < 15) ? kA6A7[s] : 0;
  if (s == 15) {
    int s2 = get_nibble(r, row1, 16, 5, kHdrTgt);
    if (s2 < 0) return -1;
    opt = kA6B7[s2 & 15];
  }
  extra_init(&gModA);
  extra_init(&gModB);
  // flag=1 → skip presence bit; otherwise both extras are 0 on fg-06.
  gExtraA = decode_opt_int(r, &gModA, 1);
  gExtraB = decode_opt_int(r, &gModB, 1);
  if (gExtraA < 0) gExtraA = 0;
  if (gExtraB < 0) gExtraB = 0;
  gHdrOff = r->off;
#ifdef HOST_TRACE
  fprintf(stderr, "hdr bit=%d s=%d opt=%02x extraA=%d extraB=%d x=%08x off=%d\n", bit, s, opt, gExtraA,
          gExtraB, r->x, r->off);
#endif
  return opt;
}

// FCM extra-class (0x14001adb0): 9-sym + bit tree, r10 is the sample.
// 0x14005fc5d(obj, extraA) writes extraA of these as dest bytes.
static int fcm_r10(Rans *r, Hist *h, uint16_t *grid, uint16_t *bits) {
  int row = hist_row(h);
  if (row < 0) row = 0;
  if (row > 80) row = 80;
  int hn = get_nibble(r, grid + row * 16, 9, 6, kNibble9Tgt);
  if (hn < 0) return -1;
  int bsf = hn + 1;
  return extra_sample(r, h, bits, bsf, hist_h1(h));
}

static int decode_v22(const uint8_t *src, int slen, uint8_t *dst, int dcap, int use_second, int use_hdr, int opt_skip = 0,
                      int force_opt = -1) {
  if (opt_skip < 0) opt_skip = 0;
  if (slen < opt_skip + 4) {
    gLastConsumed = 0;
    return 0;
  }
  src += opt_skip;
  slen -= opt_skip;
  Rans r;
  r.buf = src;
  r.off = 4;
  r.len = slen;
  r.ok = true;
  // PE 0x14002973b: movl (%rax),%r10d stores the LE dword to 0xe4(%rsp).
  // There is no renorm between that store and the first token at 0x140029e04.
  r.x = (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
  int hdr_opt = 0;
  int pre = 0;
  if (use_hdr) {
    hdr_opt = decode_opt_header(&r);
    if (hdr_opt < 0) {
      gLastConsumed = 0;
      return 0;
    }
    if (use_hdr >= 3 && use_hdr != 9 && use_hdr != 10) {
      // Option rANS (0xb40/0xb48) is independent. LZ reloads +0xb38
      // at stream+0; 0x14005fc5d emits on THAT rANS.
      r.x = (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
      r.off = 4;
      if ((use_hdr == 4 || use_hdr == 5) && gExtraB > 0 && gExtraB + 4 <= r.len) {
        // sync +0xb38 to stream.pos (parent already added extraB)
        r.off = gExtraB;
        r.x = (uint32_t)r.buf[r.off] | ((uint32_t)r.buf[r.off + 1] << 8) |
              ((uint32_t)r.buf[r.off + 2] << 16) | ((uint32_t)r.buf[r.off + 3] << 24);
        r.off += 4;
      }
    } else if (use_hdr == 2 && r.off + 4 <= r.len) {
      // Reload LE dword at the advanced 0xb48 (same as kOptSkip on a fresh rANS).
      r.x = (uint32_t)r.buf[r.off] | ((uint32_t)r.buf[r.off + 1] << 8) |
            ((uint32_t)r.buf[r.off + 2] << 16) | ((uint32_t)r.buf[r.off + 3] << 24);
      r.off += 4;
    }
  }
  const int nHi = 16384, nCls = 256 * 16, nLen = 8192, nBM = 64;
  static uint16_t hiA[16 * 16];
  static uint16_t hiB[256 * 16];
  static uint16_t loA[32 * 16];
  static uint16_t loB[256 * 16];
  // Packed 16-wide. PE model stride 34 is padding, not our row pitch.
  static uint16_t clsTab[256 * 16 * 16];
  static uint16_t lenTab[8192 * 8];
  static uint16_t off8a[32 * 8];
  static uint16_t off8b[32 * 8];
  static uint16_t off2A[16];
  static uint16_t off2B[32 * 16];
  static uint16_t off2Esc[16];
  static uint16_t off3A[16];
  static uint16_t off3B[32 * 16];
  static uint16_t off3Esc[16];
  static uint16_t off2Mid[32 * 16], off2Tail[32 * 16 * 16], off2Bp[32 * 16];
  static uint16_t off3Mid[32 * 16], off3Tail[32 * 16 * 16], off3Bp[32 * 16];
  static uint16_t off11A[16], off11A2[16], off11B[32 * 16], off11Esc[16], off11W = 0x8000;
  static uint16_t off11Mid[32 * 16], off11Tail[32 * 16 * 16], off11Bp[32 * 16];
  static uint16_t off11s0[8], off11s1[8];
  static uint16_t cls10Tab[16];
  static uint16_t offW2 = 0x8000, offW3 = 0x8000, offW11 = 0x8000;
  // Length escape 0x14006f8ad: A row esi*256+hist+flag*16 into +0x4a42a,
  // B row flag into +0xe562a (init 0x14003e612 / 0x14003e662, uniform).
  static uint16_t escA[256][16], escAe[256][16];
  static uint16_t escB[2][16], escBe[2][16];
  static uint16_t escW[256];
  // cls3 length 0x14006f962: A +0x276a6+(hist==0)*34+(bsr>>2)*68,
  // B +0x311c6+(bsr>>2)*34, then +5.
  static uint16_t c3A[16][2][16], c3Ae[16][2][16], c3B[16][16], c3W[16][2];
  static uint16_t offBits[4096];
  static uint16_t bmTab[64];
  // PE hi w: +0xc1e80 + (prev>>bm)*0x920 + hist*32 + esi*2
  // 0x920 bytes = 0x490 uint16s per (prev>>bm) row.
  static uint16_t wHi[16 * 0x490];
  static uint16_t wLo[16 * 0x490];
  for (int i = 0; i < 16; i++) init_nibble(hiA + i * 16);
  for (int i = 0; i < 256; i++) init_nibble(hiB + i * 16);
  for (int i = 0; i < 32; i++) init_nibble(loA + i * 16);
  for (int i = 0; i < 256; i++) init_nibble(loB + i * 16);
  for (int i = 0; i < nCls; i++) init_nibble(clsTab + i * 16);
  for (int i = 0; i < nLen; i++) init_sym8(lenTab + i * 8);
  for (int i = 0; i < 32; i++) {
    init_sym8(off8a + i * 8);
    init_sym8(off8b + i * 8);
    init_nibble(off2B + i * 16);
    init_nibble(off3B + i * 16);
  }
  init_nibble(off2A);
  init_nibble(off2Esc);
  init_nibble(off3A);
  init_nibble(off3Esc);
  for (int i = 0; i < 32; i++) {
    init_nibble(off2Mid + i * 16);
    init_nibble(off3Mid + i * 16);
  }
  for (int i = 0; i < 32 * 16; i++) {
    init_nibble(off2Tail + i * 16);
    init_nibble(off3Tail + i * 16);
    off2Bp[i] = kMB / 2;
    off3Bp[i] = kMB / 2;
  }
  init_nibble(off11A);
  init_nibble(off11A2);
  for (int i = 0; i < 32; i++) init_nibble(off11B + i * 16);
  init_nibble(off11Esc);
  off11W = 0x8000;
  for (int i = 0; i < 32; i++) init_nibble(off11Mid + i * 16);
  for (int i = 0; i < 32 * 16; i++) {
    init_nibble(off11Tail + i * 16);
    off11Bp[i] = kMB / 2;
  }
  init_sym8(off11s0);
  init_sym8(off11s1);
  init_nibble(cls10Tab);
  offW2 = offW3 = offW11 = 0x8000;
  for (int i = 0; i < 256; i++) {
    init_nibble(escA[i]);
    init_nibble(escAe[i]);
    escW[i] = 0x8000;
  }
  for (int i = 0; i < 2; i++) {
    init_nibble(escB[i]);
    init_nibble(escBe[i]);
  }
  for (int i = 0; i < 16; i++) {
    init_nibble(c3B[i]);
    for (int j = 0; j < 2; j++) {
      init_nibble(c3A[i][j]);
      init_nibble(c3Ae[i][j]);
      c3W[i][j] = 0x8000;
    }
  }
  for (int i = 0; i < 4096; i++) offBits[i] = kMB / 2;
  for (int i = 0; i < nBM; i++) bmTab[i] = kMB / 2;
  for (int i = 0; i < 16 * 0x490; i++) wHi[i] = 0x8000;
  for (int i = 0; i < 16 * 0x490; i++) wLo[i] = 0x8000;
  uint16_t litP[4096];
  for (int i = 0; i < 4096; i++) litP[i] = kMB / 2;
  int n = pre, prev = 0, rep0lit = 0, rep0 = 1, esi = 0;
  if (n > 0) prev = rep0lit = dst[n - 1];
  rolz_reset();
  int reps[32];
  for (int i = 0; i < 32; i++) reps[i] = 1;
  // 0x140028c49: movb al, 0x64(%r12) after decodeOpt. 0x5a98[opt] → +0xc39.
  int opt_n = force_opt >= 0 ? force_opt : (use_hdr ? hdr_opt : 0);
  if (opt_n < 0) opt_n = 0;
  if (opt_n > 36) opt_n = 36;
  const int pc_mask = kPcMask[opt_n];
  // 0x14005fc5d(obj, extraA): extraA FCM extra-class (r10) bytes, then LZ.
  if ((use_hdr == 3 || use_hdr == 4) && gExtraA > 0) {
    static uint16_t fcmGrid[81 * 16];
    static uint16_t fcmBits[9 * 1024];
    for (int i = 0; i < 81; i++) init_nibble(fcmGrid + i * 16);
    for (int i = 0; i < 9 * 1024; i++) fcmBits[i] = kMB / 2;
    Hist fh = {};
    int want = gExtraA;
    if (want > dcap) want = dcap;
    for (; n < want && r.ok; ) {
      int r10 = fcm_r10(&r, &fh, fcmGrid, fcmBits);
      if (r10 < 0) break;
      uint8_t b = (uint8_t)r10;
      dst[n] = b;
      rolz_push(prev, n);
      rolz_push(b, n);
      n++;
      prev = rep0lit = b;
      esi = kEsiTab[esi];
    }
#ifdef HOST_TRACE
    fprintf(stderr, "fc5d-fcm n=%d extraA=%d extraB=%d first=", n, gExtraA, gExtraB);
    for (int i = 0; i < n && i < 16; i++) fprintf(stderr, "%02x", dst[i]);
    if (n > 0) fprintf(stderr, " ascii=%.*s", n < 16 ? n : 16, dst);
    fprintf(stderr, "\n");
#endif
  }
  // 0x14005fc5d(obj, extraA) on the extraB window at +0xb38, then LZ
  // reloads +0xb38 from stream.pos (parent already added extraB).
  // hdr6: write extraA forced LZ lits from the window, then LZ at extraB.
  // hdr8: same lits only prime prev/models (do not write); LZ at extraB.
  if ((use_hdr == 6 || use_hdr == 8) && gExtraA > 0 && gExtraB >= 4) {
    Rans wr;
    wr.buf = src;
    wr.len = gExtraB;
    wr.ok = true;
    wr.off = 4;
    wr.x = (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
    int want = gExtraA;
    if (want > dcap) want = dcap;
    int wn = 0, wprev = prev, wesi = esi;
    for (; wn < want && wr.ok; ) {
      int ha = (wprev >> 4) & 15;
      int hb = wprev & 255;
      int wix = ha * 0x490 + wesi;
      if (wix < 0 || wix >= 16 * 0x490) wix = 0;
      int hi = get_nibble_mix(&wr, hiA + ha * 16, hiB + hb * 16, &wHi[wix], 16, 6, kMatchTgt);
      if (hi < 0) break;
      int la = ctx_lo_pe(wprev, hi);
      if (la < 0) la = 0;
      if (la > 31) la = 31;
      int lo = get_nibble_mix(&wr, loA + la * 16, loB + hb * 16, &wLo[wix], 16, 7, kNibbleTgt);
      if (lo < 0) break;
      uint8_t b = (uint8_t)((hi << 4) | lo);
      if (use_hdr == 6) {
        dst[n] = b;
        rolz_push(prev, n);
        rolz_push(b, n);
        n++;
      }
      wprev = b;
      wesi = kEsiTab[wesi];
      wn++;
    }
    prev = rep0lit = wprev;
    esi = wesi;
    if (gExtraB + 4 <= slen) {
      r.off = gExtraB;
      r.x = (uint32_t)src[r.off] | ((uint32_t)src[r.off + 1] << 8) | ((uint32_t)src[r.off + 2] << 16) |
            ((uint32_t)src[r.off + 3] << 24);
      r.off += 4;
      r.len = slen;
      r.ok = true;
    }
#ifdef HOST_TRACE
    fprintf(stderr, "fc5d-winlit hdr=%d wn=%d n=%d prev=%02x first=", use_hdr, wn, n, prev & 255);
    for (int i = 0; i < n && i < 16; i++) fprintf(stderr, "%02x", dst[i]);
    fprintf(stderr, "\n");
#endif
  }
  // 0x14005fc5d(obj, extraA): leftover option rANS (+0xb40 x=0x02004000
  // off=9) + already-adapted extra model at obj+0xb90+0x54. Init
  // 0x14003edb0 is uniform i*0x800 / p0=0x4000; extraA's 16-sym left
  // cdf[0] non-uniform. x86 0x452748 is (eax=obj, edx=extraA) only.
  if (use_hdr == 9 && gExtraA > 0) {
    ExtraModel M = gModA;
    int want = gExtraA;
    if (want > dcap) want = dcap;
    for (; n < want && r.ok; ) {
      int hi = get_nibble(&r, M.cdf[0], 16, 5, kHdrTgt);
      if (hi < 0) break;
      int lo = get_nibble(&r, M.cdf[0], 16, 5, kHdrTgt);
      if (lo < 0) break;
      uint8_t b = (uint8_t)((hi << 4) | (lo & 15));
      dst[n] = b;
      rolz_push(prev, n);
      rolz_push(b, n);
      n++;
      prev = rep0lit = b;
      esi = kEsiTab[esi];
    }
    if (gExtraB + 4 <= slen) {
      r.off = gExtraB;
      r.x = (uint32_t)src[r.off] | ((uint32_t)src[r.off + 1] << 8) | ((uint32_t)src[r.off + 2] << 16) |
            ((uint32_t)src[r.off + 3] << 24);
      r.off += 4;
      r.len = slen;
      r.ok = true;
    }
#ifdef HOST_TRACE
    fprintf(stderr, "fc5d-ad nib n=%d first=", n);
    for (int i = 0; i < n && i < 16; i++) fprintf(stderr, "%02x", dst[i]);
    fprintf(stderr, "\n");
#endif
  }
  // 0x14005fc5d via 0x140036b00: extraA dest = decode_int (lookback=prev).
  // hdr10 leftover option rANS; hdr11 fresh window rANS.
  if ((use_hdr == 10 || use_hdr == 11) && gExtraA > 0) {
    if (use_hdr == 11) {
      r.x = (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
      r.off = 4;
      r.len = gExtraB > 0 && gExtraB <= slen ? gExtraB : slen;
      r.ok = true;
    }
    IntModel im;
    int_model_init(&im);
    int want = gExtraA;
    if (want > dcap) want = dcap;
    for (; n < want && r.ok; ) {
      int v = decode_int_pe(&r, &im, prev);
      if (v < 0) break;
      uint8_t b = (uint8_t)v;
      dst[n] = b;
      rolz_push(prev, n);
      rolz_push(b, n);
      n++;
      prev = rep0lit = b;
      esi = kEsiTab[esi];
    }
    if (gExtraB + 4 <= slen) {
      r.off = gExtraB;
      r.x = (uint32_t)src[r.off] | ((uint32_t)src[r.off + 1] << 8) | ((uint32_t)src[r.off + 2] << 16) |
            ((uint32_t)src[r.off + 3] << 24);
      r.off += 4;
      r.len = slen;
      r.ok = true;
    }
#ifdef HOST_TRACE
    fprintf(stderr, "fc5d-int hdr=%d n=%d first=", use_hdr, n);
    for (int i = 0; i < n && i < 16; i++) fprintf(stderr, "%02x", dst[i]);
    if (n > 0) fprintf(stderr, " ascii=%.*s", n < 16 ? n : 16, dst);
    fprintf(stderr, "\n");
#endif
  }
  // 0x14005fc5d(obj, extraA) @ default +0xc24==0.
  // v22 body is past SizeOfImage 0x57000. v20 cousin call 0x14001ecb4
  // lands mid-movdqu of a CDF-init (not a dest writer). In-image dest
  // stores are only LZ lit / match / opt==0x3f memcpy. The only in-image
  // integer decoder with this prototype family is 0x14003b430
  // (flag=1, nbits=6, A at model+0x54). Parent left +0xb38 at stream+0
  // (the extraB window); LZ later reloads a fresh LE dword from +0xb38
  // and continues at dest[+0x58].
  if (use_hdr == 12 && gExtraA > 0) {
    ExtraModel M;
    extra_init(&M);
    int want = gExtraA;
    if (want > dcap) want = dcap;
    for (; n < want && r.ok;) {
      int v = decode_opt_int(&r, &M, 1);
      if (v < 0) break;
      uint8_t b = (uint8_t)v;
      dst[n] = b;
      rolz_push(prev, n);
      rolz_push(b, n);
      n++;
      prev = rep0lit = b;
      esi = kEsiTab[esi];
    }
    // Parent did not move +0xb38. LZ 0x140029700 reloads stream+0.
    r.x = (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
    r.off = 4;
    r.len = slen;
    r.ok = true;
#ifdef HOST_TRACE
    fprintf(stderr, "fc5d-b430 n=%d extraA=%d first=", n, gExtraA);
    for (int i = 0; i < n && i < 16; i++) fprintf(stderr, "%02x", dst[i]);
    if (n > 0) fprintf(stderr, " ascii=%.*s", n < 16 ? n : 16, dst);
    fprintf(stderr, "\n");
#endif
  }
  // In-image raw +0x58 cousin (0x140028d7f / memcpy 0x1400676b5): extraA
  // bytes from the extraB window, then LZ reloads stream.pos.
  if (use_hdr == 7 && gExtraA > 0 && gExtraB > 0) {
    int want = gExtraA;
    if (want > gExtraB) want = gExtraB;
    if (want > dcap) want = dcap;
    memcpy(dst, src, (size_t)want);
    n = want;
    prev = rep0lit = dst[n - 1];
    for (int i = 0; i < n; i++) esi = kEsiTab[esi];
    if (gExtraB + 4 <= slen) {
      r.off = gExtraB;
      r.x = (uint32_t)src[r.off] | ((uint32_t)src[r.off + 1] << 8) | ((uint32_t)src[r.off + 2] << 16) |
            ((uint32_t)src[r.off + 3] << 24);
      r.off += 4;
      r.len = slen;
      r.ok = true;
    }
  }
  while (n < dcap && n < kWant && r.ok) {
    if (r.x < kL && r.off >= r.len) break;
    int hist = kHistTab[opt_n][n & pc_mask];
    int mix = kMixTab[hist];
    // p0 at model+0xb50 + (hist<<6) + esi*4  (0x140029e53)
    int pctx = hist * 32 + esi * 2;
    if (pctx < 0 || pctx + 1 >= 4096) break;
#ifdef HOST_TRACE
    if (n < 3) fprintf(stderr, "pre-tok n=%d x=%08x p0=%04x pctx=%d\n", n, r.x, litP[pctx], pctx);
#endif
    int bit = get_bit(&r, &litP[pctx], 14, 5);
    if (bit < 0) break;
#ifdef HOST_TRACE
    if (n < 3) fprintf(stderr, "post-tok n=%d bit=%d x=%08x p0=%04x\n", n, bit, r.x, litP[pctx]);
#endif
    int tok = bit; // 0=lit 1=match; 2=DXT if mixer<99 and second bit
    if (use_second && bit == 0 && mix < 0x63) {
      int b2 = get_bit(&r, &litP[pctx + 1], 14, 5);
      if (b2 < 0) break;
      if (b2 == 1) tok = 2;
    }
    if (tok == 0) {
      // defaults -blr4 -blo8 -bll8 -bm4 → shifts 4,0,0,4
      int ha = (prev >> 4) & 15;
      int hb = prev & 255;
#ifdef HOST_TRACE
      if (n < 3) fprintf(stderr, "pre-hi n=%d x=%08x ha=%d hb=%d\n", n, r.x, ha, hb);
#endif
      // PE: w at (prev>>bm)*0x920 + hist*32 + esi*2. hist=0, bm=4.
      int wix = ha * 0x490 + esi;
      if (wix < 0 || wix >= 16 * 0x490) wix = 0;
#if defined(HOST_DEBUG) && !defined(HOST_QUIET)
      if (n < 8) fprintf(stderr, "pre-hi n=%d x=%08x slot=%04x ha=%d hb=%d esi=%d w=%04x\n", n, r.x, r.x & 0x7fff, ha, hb, esi, wHi[wix]);
#endif
      int hi = get_nibble_mix(&r, hiA + ha * 16, hiB + hb * 16, &wHi[wix], 16, 6, kMatchTgt);
      if (hi < 0) break;
#ifdef TRACE_TOK
      if (n < 4) fprintf(stderr, "post-hi n=%d hi=%d x=%08x slot=%04x\n", n, hi, r.x, r.x & 0x7fff);
#endif
      int la = ctx_lo_pe(prev, hi);
      if (la < 0) la = 0;
      if (la > 31) la = 31;
#ifdef TRACE_TOK
      if (n < 8) fprintf(stderr, "pre-lo n=%d x=%08x slot=%04x la=%d w=%04x\n", n, r.x, r.x & 0x7fff, la, wLo[wix]);
#endif
      int lo = get_nibble_mix(&r, loA + la * 16, loB + hb * 16, &wLo[wix], 16, 7, kNibbleTgt);
      if (lo < 0) break;
      uint8_t b = (uint8_t)((hi << 4) | lo);
#ifdef TRACE_TOK
      if (n < 70) fprintf(stderr, "lit n=%d b=%02x hi=%d lo=%d x=%08x slot=%04x esi=%d\n", n, b, hi, lo, r.x, r.x & 0x7fff, esi);
#endif
      dst[n] = b;
      rolz_push(prev, n);
      rolz_push(b, n);
      n++;
      prev = rep0lit = b;
      esi = kEsiTab[esi];
      continue;
    }
    if (tok == 2) {
#ifdef TRACE_TOK
      fprintf(stderr, "stop dxt n=%d mix=%d x=%08x\n", n, mix, r.x);
#endif
      break;
    }
    // class CDF at *(+0xb50)+0x1240 + esi*544 + hist*34 (0x140039b04).
    // Packed 16-wide: crow = esi*16 + hist. Axes were swapped.
    int crow = esi * 16 + hist;
    if (crow >= nCls) crow = nCls - 1;
#ifdef TRACE_TOK
    if (n < 70) fprintf(stderr, "pre-cls n=%d x=%08x slot=%04x crow=%d esi=%d\n", n, r.x, r.x & 0x7fff, crow, esi);
#endif
    int cls = get_nibble(&r, clsTab + crow * 16, 16, 6, kMatchTgt);
#ifdef TRACE_TOK
    if (n < 70) fprintf(stderr, "post-cls n=%d cls=%d x=%08x slot=%04x\n", n, cls, r.x, r.x & 0x7fff);
#endif
    // PE 0x140039bf9: cmp r15, 0xb / ja 0x14003a3a0 — cls 12-15 are
    // reps[cls-12] with rotate and immediate length 2, not an error.
    if (cls < 0 || cls > 15) {
#ifdef TRACE_TOK
      fprintf(stderr, "stop cls n=%d cls=%d crow=%d x=%08x\n", n, cls, crow, r.x);
#endif
      break;
    }
    int extra = 0;
    int m_fixed = -1;
    if (cls == 1) {
      // s0 at +0x1c560 adapt >>6 / 0x11a0; s1 at +0x1ca82 >>7 / 0x2f20
      // lea rbp,[rcx+rbp*8] (0-based == x86 lea ebx,[eax+edx*8-9])
      // bytes after that lea: f9 99 03 00 00 (objdump desyncs); twin
      // 0x14003626f is mov edi,2 so length is the immediate 2.
      int arow = hist % 32;
      int s0 = get_sym8_tgt(&r, off8a + arow * 8, kOff8Tgt, 6);
      if (s0 < 0) break;
      int brow = ((prev >= 10 ? 8 : 0) + s0) % 32;
      int s1 = get_sym8_tgt(&r, off8b + brow * 8, kLen8Tgt, 7);
      if (s1 < 0) break;
      extra = s1 + s0 * 8;
      if (extra < 1) extra = 1;
    } else if (cls == 2) {
      int brow = bitlen((uint32_t)rep0) % 32;
      extra = decode_new_off(&r, off2A, off2B + brow * 16, &offW2, off2Esc, off2Bp, kA6E7,
                            (int)sizeof(kA6E7), off2Mid, off2Tail);
      if (extra < 0) break;
    } else if (cls == 3) {
      int brow = bitlen((uint32_t)rep0) % 32;
      extra = decode_new_off(&r, off3A, off3B + brow * 16, &offW3, off3Esc, off3Bp, kA6E7,
                            (int)sizeof(kA6E7), off3Mid, off3Tail);
      if (extra < 0) break;
    } else if (cls == 11) {
      // 0x140039c1d: two decode_int cousins on model +0xb68, not +0xbc0.
      // 1st: mix16+esc+a6e7 → length base. 2nd: same shape, lookback=first.
      // Then ROLZ list[prev][cur + ~idx], length = first+2.
      int ln, idx;
      if (gCls11Mode >= 6) {
        ln = decode_mix16_esc(&r, off11A, off11B, &offW11, off11Esc);
        if (ln < 0) break;
        idx = decode_cls11_idx(&r, ln, off11B, off11Esc, off11Bp);
        if (idx < 0) break;
      } else if (gCls11Mode >= 3) {
        ln = decode_mix16_esc(&r, off11A, off11B, &offW11, off11Esc);
        if (ln < 0) break;
        int brow = bitlen((uint32_t)ln) % 32;
        idx = decode_mix16_esc(&r, off11A2, off11B + brow * 16, &off11W, off11Esc);
        if (idx < 0) break;
      } else {
        ln = decode_new_off(&r, off11A, off11B, &offW11, off11Esc, off11Bp, kA6E7,
                            (int)sizeof(kA6E7), off11Mid, off11Tail);
        if (ln < 0) break;
        idx = decode_cls11_idx(&r, ln, off11B, off11Esc, off11Bp);
        if (idx < 0) break;
      }
      int how = gCls11Mode % 3;
      if (how == 1) extra = idx;
      else if (how == 2) extra = idx + 1;
      else extra = rolz_lookup(prev, idx, n);
      m_fixed = ln + 2;
    } else if (cls == 10) {
      // PE: 16-sym at model+0x364ca, not the class row. a697[sym] = index.
      int s = get_nibble(&r, cls10Tab, 16, 6, kMatchTgt);
      if (s < 0) break;
      extra = kA697[s & 15];
    }
    int dist = decode_off(cls, extra, &rep0, reps, 32);
    int m;
    if (m_fixed >= 0) {
      m = m_fixed;
    } else if (cls == 0) {
      // 0x14003a396: class 0 length is the immediate 1, no 8-sym.
      m = 1;
    } else if (cls == 1 || (cls >= 12 && cls <= 15)) {
      // cls1: mov edi,2. cls12-15 @ 0x14003a3f6: movl $2, %ebx.
      m = 2;
    } else if (cls == 2) {
      // p0 at +0x21ca2 + (bsr(off)+1 & ~3) + hist*32 + (hist==0?2:0)
      // scale 14 adapt >>5 (0x14003a121). r13 is hist, not prev.
      int bl = bitlen((uint32_t)dist) & ~3;
      int bctx = (bl + hist * 32 + (hist == 0 ? 2 : 0)) % nBM;
      int b = get_bit(&r, &bmTab[bctx], 14, 5);
      if (b < 0) break;
      m = 3 + b;
    } else if (cls == 3) {
      // 0x14003a09d: call 0x14006f962 / add $5. Same mix16+esc as
      // length-escape; A/B rows from bsr(off)>>2 and hist==0.
      int h0 = hist == 0 ? 1 : 0;
      int bl = bitlen((uint32_t)dist) >> 2;
      if (bl < 0) bl = 0;
      if (bl > 15) bl = 15;
      int en = decode_mix16_esc(&r, c3A[bl][h0], c3B[bl], &c3W[bl][h0], c3Ae[bl][h0]);
      if (en < 0) break;
      m = 5 + en;
#ifdef TRACE_TOK
      if (n < 80) fprintf(stderr, "cls3len n=%d en=%d m=%d bl=%d x=%08x\n", n, en, m, bl, r.x);
#endif
    } else {
      // 0x140039ec8: esi*576 + hist*36 + (idx!=0)*18 + 0x3ffea
      // packed 8-wide: esi*32 + hist*2 + flag.
      int idxflag = 0;
      if (cls >= 4 && cls <= 9) idxflag = kA690[cls - 4] != 0;
      else if (cls == 10) idxflag = extra != 0;
      else idxflag = extra != 0;
      int lrow = esi * 32 + hist * 2 + idxflag;
      if (lrow >= nLen) lrow = nLen - 1;
      int ln = get_sym8(&r, lenTab + lrow * 8);
      if (ln < 0) break;
      m = ln + 3;
#ifdef TRACE_TOK
      if (n < 40) fprintf(stderr, "len8 n=%d ln=%d m=%d x=%08x slot=%04x lrow=%d\n", n, ln, m, r.x, r.x & 0x7fff, lrow);
#endif
      if (m == 10) {
        // 0x140039f8e: cmp $0xa / call 0x14006f8ad / add $0xa.
        // flag = seta after test rdx (a690 idx / new-off), *544 / *34.
        int idxflag = 0;
        if (cls >= 4 && cls <= 9) idxflag = kA690[cls - 4] != 0;
        else if (cls == 10) idxflag = extra != 0;
        else idxflag = extra != 0;
        int arow = ((esi & 127) << 1) | (idxflag ? 1 : 0);
        int brow = idxflag ? 1 : 0;
        int en = decode_mix16_esc(&r, escA[arow], escB[brow], &escW[arow], escAe[arow]);
        if (en < 0) break;
        m = 10 + en;
#ifdef TRACE_TOK
        fprintf(stderr, "lenesc n=%d en=%d m=%d x=%08x arow=%d brow=%d\n", n, en, m, r.x, arow, brow);
#endif
      }
    }
#ifdef TRACE_TOK
    if (n < 80 || cls == 11)
      fprintf(stderr, "match n=%d cls=%d extra=%d m=%d dist=%d rep0=%d esi=%d x=%08x\n", n, cls, extra, m, dist, rep0, esi, r.x);
#endif
    if (m <= 0 || dist < 0) {
#ifdef TRACE_TOK
      fprintf(stderr, "stop match n=%d cls=%d m=%d dist=%d x=%08x\n", n, cls, m, dist, r.x);
#endif
      break;
    }
#ifdef TRACE_TOK
    if (dist > n && n > 0) {
      static int once;
      if (once < 3) {
        fprintf(stderr, "oversize n=%d cls=%d m=%d dist=%d x=%08x\n", n, cls, m, dist, r.x);
        once++;
      }
    }
#endif
#ifdef TRACE_TOK
    if (n < kEmu && n + m >= kEmu) {
      fprintf(stderr, "cover2895 n=%d cls=%d m=%d dist=%d prev=%02x x=%08x\n", n, cls, m, dist,
              prev & 255, r.x);
    }
#endif
    // PE dict is VirtualAlloc zeros: dist>n copies 0 (same as pos==0 wrap).
    for (int i = 0; i < m && n < dcap && n < kWant; i++) {
      uint8_t b = (dist > 0 && dist <= n) ? dst[n - dist] : 0;
      dst[n] = b;
      rolz_push(prev, n);
      rolz_push(b, n);
      prev = b;
      n++;
    }
    if (n > 0) rep0lit = dst[n - 1];
    esi = esi_after_match(esi, cls, hist);
  }
#ifdef TRACE_TOK
  fprintf(stderr, "end n=%d x=%08x off=%d ok=%d\n", n, r.x, r.off, (int)r.ok);
  if (n > kEmu + 8) {
    fprintf(stderr, "around2895=");
    int a = kEmu - 16;
    if (a < 0) a = 0;
    for (int i = a; i < kEmu + 16 && i < n; i++) fprintf(stderr, "%02x", dst[i]);
    fprintf(stderr, "\n");
  }
#endif
  gLastConsumed = opt_skip + r.off;
  return n;
}

static int peek_opt(const uint8_t *src, int slen) {
  if (slen < 4) return 0;
  Rans r;
  r.buf = src;
  r.off = 4;
  r.len = slen;
  r.ok = true;
  r.x = (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
  int o = decode_opt_header(&r);
  return o < 0 ? 0 : o;
}

extern "C" int magic2_get_input_consumed(void) { return gLastConsumed; }

extern "C" int magic2_decode(const uint8_t *src, int slen, uint8_t *dst, int dcap) {
  if (!src || slen < 4 || !dst || dcap <= 0) return 0;
  int opt = peek_opt(src, slen);
  // Default +0xc24==0: decodeOpt extras, 0x14005fc5d(obj, extraA), LZ.
  {
    gCls11Mode = 0;
    int n = decode_v22(src, slen, dst, dcap, 1, 12, 0, opt);
    if (hit_crc(dst, n)) return n;
    if (n >= 4 && (dst[0] == '[' || dst[0] == ';')) return n;
  }
  // Default +0xc24==0: decodeOpt extras then 0x14005fc5d(obj, extraA), LZ.
  for (int m = 0; m < 9; m++) {
    gCls11Mode = m;
    int n = decode_v22(src, slen, dst, dcap, 1, 3, 0, opt);
    if (hit_crc(dst, n)) return n;
    n = decode_v22(src, slen, dst, dcap, 1, 4, 0, opt);
    if (hit_crc(dst, n)) return n;
    n = decode_v22(src, slen, dst, dcap, 1, 5, 0, opt);
    if (hit_crc(dst, n)) return n;
  }
  gCls11Mode = 0;
  int n = decode_v22(src, slen, dst, dcap, 1, 3, 0, opt);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 1, 4, 0, opt);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 1, 5, 0, opt);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 1, 6, 0, opt);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 1, 7, 0, opt);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 1, 8, 0, opt);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 1, 9, 0, opt);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 1, 10, 0, opt);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 1, 11, 0, opt);
  if (hit_crc(dst, n)) return n;
  // PE: decodeOpt writes +0x64; LZ reloads +0xb38 at stream pos 0 (separate rANS).
  for (int m = 0; m < 9; m++) {
    gCls11Mode = m;
    n = decode_v22(src, slen, dst, dcap, 1, 0, 0, opt);
    if (hit_crc(dst, n)) return n;
  }
  gCls11Mode = 0;
  n = decode_v22(src, slen, dst, dcap, 1, 0, 0);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 1, 0, kOptSkip, opt);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 0, 0, 0);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 1, 1, 0);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 1, 2, 0);
  if (hit_crc(dst, n)) return n;
  n = decode_v22(src, slen, dst, dcap, 0, 1, 0);
  if (hit_crc(dst, n)) return n;
  n = decode_iir(src, slen, dst, dcap, 5);
  if (hit_crc(dst, n)) return n;
  n = decode_iir(src, slen, dst, dcap, 4);
  if (hit_crc(dst, n)) return n;
  // Default emit: +0xc24==0 0x14005fc5d then LZ at dest[+0x58].
  return decode_v22(src, slen, dst, dcap, 1, 12, 0, opt);
}

#ifdef HOST_DEBUG
static void show_prefix(const char *tag, const uint8_t *p, int n);

static void leftover_opt(Rans *r, const uint8_t *src, int slen, ExtraModel *A, ExtraModel *B) {
  r->buf = src;
  r->len = slen;
  r->ok = true;
  r->off = 4;
  r->x = (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
  extra_init(A);
  extra_init(B);
  uint16_t ptab[2] = {0x4000, 0x4000};
  get_bit(r, &ptab[0], 15, 5);
  uint16_t row0[16], row1[16];
  init_nibble(row0);
  init_nibble(row1);
  int s = get_nibble(r, row0, 16, 5, kHdrTgt);
  if (s == 15) get_nibble(r, row1, 16, 5, kHdrTgt);
  decode_opt_int(r, A, 1);
  decode_opt_int(r, B, 1);
}

// Leftover option rANS + already-adapted extra model (model+0x54 after extraA).
static void probe_fc5d_adapted(const uint8_t *src, int slen) {
  ExtraModel A, B;
  Rans r;
  leftover_opt(&r, src, slen, &A, &B);
  uint8_t out[64];
  int extraA = gExtraA > 0 ? gExtraA : 16;
  // nbits=6 dest: 6 get_bits on leftover, map through 0x20/0x40 (printable 6-bit).
  // 0x14003b430 hardcodes mask 0x3f; does not read stack nbits.
  {
    ExtraModel M = A;
    for (int lsb = 0; lsb < 2; lsb++) {
      for (int add = 0; add <= 0x40; add += 0x20) {
        Rans rr = r;
        ExtraModel MM = M;
        int rdx = 1, n = 0;
        for (; n < extraA && rr.ok; n++) {
          int v = 0;
          for (int k = 0; k < 6; k++) {
            int off = 5 * 64 + rdx;
            if (off >= kExtraBits) off = kExtraBits - 1;
            int b = get_bit(&rr, &MM.bits[off], 15, 4);
            if (b < 0) {
              rr.ok = false;
              break;
            }
            rdx = (b + 2 * rdx) & 0x3f;
            if (lsb) v |= b << k;
            else v = (v << 1) | b;
          }
          if (!rr.ok) break;
          out[n] = (uint8_t)((v & 0x3f) + add);
        }
        char tag[40];
        snprintf(tag, sizeof(tag), "6bit lsb%d +%02x", lsb, add);
        show_prefix(tag, out, n);
      }
    }
    // row = ctxa * 0x44/34: one 16-sym per dest from leftover
    {
      Rans rr = r;
      ExtraModel MM = A;
      int n = 0;
      int ctx = MM.ctxa > 15 ? 15 : MM.ctxa;
      for (; n < extraA && rr.ok; n++) {
        int s = get_nibble(&rr, MM.cdf[ctx], 16, 5, kHdrTgt);
        if (s < 0) break;
        out[n] = (uint8_t)s;
        ctx = (s + 1) > 15 ? 15 : (s + 1);
      }
      show_prefix("row-ctxa-sym", out, n);
    }
  }
  fprintf(stderr, "adapted leftover x=%08x off=%d ctx8=%d ctxa=%d p0=%04x cdf0=", r.x, r.off, A.ctx8, A.ctxa,
          A.p0[0]);
  for (int i = 0; i < 16; i++) fprintf(stderr, "%04x ", A.cdf[0][i]);
  fprintf(stderr, "\n");

  // nibble-pairs from adapted cdf[0] / current ctxa / walk ctx
  for (int mode = 0; mode < 3; mode++) {
    ExtraModel M = A;
    Rans rr = r;
    int n = 0;
    for (; n < extraA && rr.ok; n++) {
      int ctx = (mode == 0) ? 0 : (mode == 1) ? (M.ctxa > 15 ? 15 : M.ctxa) : (n & 15);
      int hi = get_nibble(&rr, M.cdf[ctx], 16, 5, kHdrTgt);
      if (hi < 0) break;
      int lo = get_nibble(&rr, M.cdf[ctx], 16, 5, kHdrTgt);
      if (lo < 0) break;
      out[n] = (uint8_t)((hi << 4) | (lo & 15));
    }
    char tag[40];
    snprintf(tag, sizeof(tag), "ad-nib mode%d", mode);
    show_prefix(tag, out, n);
  }

  // 8 bits from adapted bit tree (start at extraA's last tree walk)
  for (int lsb = 0; lsb < 2; lsb++) {
    for (int base = 0; base < 8; base++) {
      ExtraModel M = A;
      Rans rr = r;
      int n = 0;
      int rdx = 1;
      for (; n < extraA && rr.ok; n++) {
        int b = 0;
        for (int k = 0; k < 8; k++) {
          int off = (4 + base) * 64 + rdx;
          if (off < 0) off = 0;
          if (off >= kExtraBits) off = kExtraBits - 1;
          int bit = get_bit(&rr, &M.bits[off], 15, 4);
          if (bit < 0) {
            rr.ok = false;
            break;
          }
          rdx = (bit + 2 * rdx) & 0x3f;
          if (lsb) b |= bit << k;
          else b = (b << 1) | bit;
        }
        if (!rr.ok) break;
        out[n] = (uint8_t)b;
      }
      char tag[40];
      snprintf(tag, sizeof(tag), "ad-tree lsb%d b%d", lsb, base);
      show_prefix(tag, out, n);
    }
  }

  // presence-bit token: 0 = nibble-pair, 1 = decode_int low 8
  {
    ExtraModel M = A;
    Rans rr = r;
    int n = 0;
    for (; n < extraA && rr.ok; n++) {
      int v = decode_opt_int(&rr, &M, 0);
      if (v < 0) break;
      if (v == 0) {
        int hi = get_nibble(&rr, M.cdf[M.ctxa > 15 ? 15 : M.ctxa], 16, 5, kHdrTgt);
        int lo = get_nibble(&rr, M.cdf[M.ctxa > 15 ? 15 : M.ctxa], 16, 5, kHdrTgt);
        if (hi < 0 || lo < 0) break;
        out[n] = (uint8_t)((hi << 4) | (lo & 15));
      } else {
        out[n] = (uint8_t)v;
      }
    }
    show_prefix("ad-tok", out, n);
  }

  // decode_int skip0 / skip1 as dest
  for (int sk = 0; sk < 2; sk++) {
    ExtraModel M = A;
    Rans rr = r;
    int n = 0;
    for (; n < extraA && rr.ok; n++) {
      int v = decode_opt_int(&rr, &M, sk);
      if (v < 0) break;
      out[n] = (uint8_t)v;
    }
    char tag[24];
    snprintf(tag, sizeof(tag), "ad-int sk%d", sk);
    show_prefix(tag, out, n);
  }

  // single 16-sym from adapted cdf[0] as dest
  {
    ExtraModel M = A;
    Rans rr = r;
    int n = 0;
    for (; n < extraA && rr.ok; n++) {
      int s = get_nibble(&rr, M.cdf[0], 16, 5, kHdrTgt);
      if (s < 0) break;
      out[n] = (uint8_t)s;
    }
    show_prefix("ad-sym0", out, n);
  }

  // Continue decodeOpt first-bit p0 (adapted >>5 after bit=0 → 0x4200).
  {
    Rans rr;
    ExtraModel dummyA, dummyB;
    uint16_t ptab[2] = {0x4000, 0x4000};
    rr.buf = src;
    rr.len = slen;
    rr.ok = true;
    rr.off = 4;
    rr.x = (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
    extra_init(&dummyA);
    extra_init(&dummyB);
    int bit = get_bit(&rr, &ptab[0], 15, 5);
    uint16_t row0[16], row1[16];
    init_nibble(row0);
    init_nibble(row1);
    int s = get_nibble(&rr, row0, 16, 5, kHdrTgt);
    if (s == 15) get_nibble(&rr, row1, 16, 5, kHdrTgt);
    decode_opt_int(&rr, &dummyA, 1);
    decode_opt_int(&rr, &dummyB, 1);
    fprintf(stderr, "hdr-p0 leftover ptab0=%04x ptab1=%04x bit=%d x=%08x off=%d\n", ptab[0], ptab[1], bit, rr.x, rr.off);
    for (int lsb = 0; lsb < 2; lsb++) {
      for (int useidx = 0; useidx < 2; useidx++) {
        Rans r2 = rr;
        uint16_t p2[2] = {ptab[0], ptab[1]};
        int idx = 0;
        int n = 0;
        for (; n < extraA && r2.ok; n++) {
          int b = 0;
          for (int k = 0; k < 8; k++) {
            int bt = get_bit(&r2, &p2[useidx ? idx : 0], 15, 5);
            if (bt < 0) {
              r2.ok = false;
              break;
            }
            if (useidx) idx = bt;
            if (lsb) b |= bt << k;
            else b = (b << 1) | bt;
          }
          if (!r2.ok) break;
          out[n] = (uint8_t)b;
        }
        char tag[40];
        snprintf(tag, sizeof(tag), "hdr-p0 lsb%d idx%d", lsb, useidx);
        show_prefix(tag, out, n);
      }
    }
    // continue header 16-sym CDF (adapted toward 0)
    {
      Rans r2 = rr;
      uint16_t cdf[16];
      memcpy(cdf, row0, sizeof(cdf));
      int n = 0;
      for (; n < extraA && r2.ok; n++) {
        int hi = get_nibble(&r2, cdf, 16, 5, kHdrTgt);
        int lo = get_nibble(&r2, cdf, 16, 5, kHdrTgt);
        if (hi < 0 || lo < 0) break;
        out[n] = (uint8_t)((hi << 4) | (lo & 15));
      }
      show_prefix("hdr-cdf-nib", out, n);
      r2 = rr;
      memcpy(cdf, row0, sizeof(cdf));
      n = 0;
      for (; n < extraA && r2.ok; n++) {
        int s2 = get_nibble(&r2, cdf, 16, 5, kHdrTgt);
        if (s2 < 0) break;
        out[n] = (uint8_t)s2;
      }
      show_prefix("hdr-cdf-sym", out, n);
    }
  }

  // LZ lits from leftover option rANS (fresh LZ models, leftover state)
  {
    Rans rr = r;
    uint16_t hiA[16 * 16], hiB[256 * 16], loA[32 * 16], loB[256 * 16];
    uint16_t wHi[16 * 0x490], wLo[16 * 0x490];
    for (int i = 0; i < 16; i++) init_nibble(hiA + i * 16);
    for (int i = 0; i < 256; i++) init_nibble(hiB + i * 16);
    for (int i = 0; i < 32; i++) init_nibble(loA + i * 16);
    for (int i = 0; i < 256; i++) init_nibble(loB + i * 16);
    for (int i = 0; i < 16 * 0x490; i++) wHi[i] = wLo[i] = 0x8000;
    int n = 0, prev = 0, esi = 0;
    for (; n < extraA && rr.ok; n++) {
      int ha = (prev >> 4) & 15;
      int hb = prev & 255;
      int wix = ha * 0x490 + esi;
      int hi = get_nibble_mix(&rr, hiA + ha * 16, hiB + hb * 16, &wHi[wix], 16, 6, kMatchTgt);
      if (hi < 0) break;
      int la = ctx_lo_pe(prev, hi);
      if (la < 0) la = 0;
      if (la > 31) la = 31;
      int lo = get_nibble_mix(&rr, loA + la * 16, loB + hb * 16, &wLo[wix], 16, 7, kNibbleTgt);
      if (lo < 0) break;
      out[n] = (uint8_t)((hi << 4) | lo);
      prev = out[n];
      esi = kEsiTab[esi];
    }
    show_prefix("ad-lzlit", out, n);
  }
}

static void show_prefix(const char *tag, const uint8_t *p, int n) {
  fprintf(stderr, "%s n=%d first=", tag, n);
  for (int i = 0; i < n && i < 16; i++) fprintf(stderr, "%02x", p[i]);
  int pr = 0;
  for (int i = 0; i < n && i < 16; i++) {
    uint8_t c = p[i];
    if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) pr++;
  }
  if (n > 0) fprintf(stderr, " ascii=%.*s pr=%d", n < 16 ? n : 16, p, pr);
  if (n > 0 && (p[0] == '[' || p[0] == ';' || p[0] == 'S')) fprintf(stderr, " INI");
  fprintf(stderr, "\n");
}

// Probe 0x14005fc5d cousins: extraA dest bytes from the extraB window / leftover option rANS.
static void probe_fc5d_window(const uint8_t *src, int slen) {
  ExtraModel savedA = gModA, savedB = gModB;
  int extraA = gExtraA, extraB = gExtraB, hdrOff = gHdrOff;
  fprintf(stderr, "probe window extraA=%d extraB=%d hdroff=%d\n", extraA, extraB, hdrOff);
  if (extraB < 4 || extraB > slen) return;
  const uint8_t *win = src;
  auto win_rans = [&](Rans *r, int from) {
    r->buf = win;
    r->len = extraB;
    r->ok = true;
    if (from + 4 > extraB) {
      r->off = extraB;
      r->x = 0;
      r->ok = false;
      return;
    }
    r->off = from + 4;
    r->x = (uint32_t)win[from] | ((uint32_t)win[from + 1] << 8) | ((uint32_t)win[from + 2] << 16) |
           ((uint32_t)win[from + 3] << 24);
  };
  auto leftover = [&](Rans *r) {
    r->buf = src;
    r->len = slen;
    r->ok = true;
    r->off = hdrOff;
    // Recreate leftover option rANS by replaying extras.
    r->x = (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
    r->off = 4;
    ExtraModel dumpA, dumpB;
    extra_init(&dumpA);
    extra_init(&dumpB);
    uint16_t ptab[2] = {0x4000, 0x4000};
    int bit = get_bit(r, &ptab[0], 15, 5);
    (void)bit;
    uint16_t row0[16], row1[16];
    init_nibble(row0);
    init_nibble(row1);
    int s = get_nibble(r, row0, 16, 5, kHdrTgt);
    if (s == 15) get_nibble(r, row1, 16, 5, kHdrTgt);
    decode_opt_int(r, &dumpA, 1);
    decode_opt_int(r, &dumpB, 1);
  };

  uint8_t out[64];

  // 8 binary bits / dest byte (get_bit 0x14001af4a cousin).
  for (int srcmode = 0; srcmode < 2; srcmode++) {
    for (int nbits = 14; nbits <= 15; nbits++) {
      for (int lsb = 0; lsb < 2; lsb++) {
        for (int adapt = 4; adapt <= 5; adapt++) {
          Rans r;
          if (srcmode == 0) win_rans(&r, 0);
          else leftover(&r);
          uint16_t p0[16];
          for (int i = 0; i < 16; i++) p0[i] = (nbits == 14) ? 0x2000 : 0x4000;
          int n = 0;
          for (; n < extraA && r.ok; n++) {
            int b = 0;
            for (int k = 0; k < 8; k++) {
              int bit = get_bit(&r, &p0[k & 15], (unsigned)nbits, (unsigned)adapt);
              if (bit < 0) {
                r.ok = false;
                break;
              }
              if (lsb) b |= bit << k;
              else b = (b << 1) | bit;
            }
            if (!r.ok) break;
            out[n] = (uint8_t)b;
          }
          char tag[80];
          snprintf(tag, sizeof(tag), "bits %s s%d lsb%d a%d", srcmode ? "opt" : "win", nbits, lsb, adapt);
          show_prefix(tag, out, n);
        }
      }
    }
  }

  // Nibble-pairs from leftover extra model / fresh model, window or option rANS.
  for (int srcmode = 0; srcmode < 2; srcmode++) {
    for (int reuse = 0; reuse < 2; reuse++) {
      Rans r;
      if (srcmode == 0) win_rans(&r, 0);
      else leftover(&r);
      ExtraModel A = reuse ? savedA : ExtraModel{};
      if (!reuse) extra_init(&A);
      int n = 0;
      for (; n < extraA && r.ok; n++) {
        int hi = get_nibble(&r, A.cdf[A.ctxa & 15], 16, 5, kHdrTgt);
        if (hi < 0) break;
        int lo = get_nibble(&r, A.cdf[(A.ctxa + 1) & 15], 16, 5, kHdrTgt);
        if (lo < 0) break;
        out[n] = (uint8_t)((hi << 4) | (lo & 15));
      }
      char tag[80];
      snprintf(tag, sizeof(tag), "nibpair %s reuse%d", srcmode ? "opt" : "win", reuse);
      show_prefix(tag, out, n);
    }
  }

  // FCM extra-class extraA from window vs leftover option rANS.
  for (int srcmode = 0; srcmode < 2; srcmode++) {
    Rans r;
    if (srcmode == 0) win_rans(&r, 0);
    else leftover(&r);
    uint16_t grid[81 * 16];
    uint16_t bits[9 * 1024];
    for (int i = 0; i < 81; i++) init_nibble(grid + i * 16);
    for (int i = 0; i < 9 * 1024; i++) bits[i] = kMB / 2;
    Hist fh = {};
    int n = 0;
    for (; n < extraA && r.ok; n++) {
      int v = fcm_r10(&r, &fh, grid, bits);
      if (v < 0) break;
      out[n] = (uint8_t)v;
    }
    show_prefix(srcmode ? "fcm-opt" : "fcm-win", out, n);
  }

  // Forced LZ literals (no match bit) extraA from window, then leftover state.
  {
    Rans r;
    win_rans(&r, 0);
    uint16_t hiA[16 * 16], hiB[256 * 16], loA[32 * 16], loB[256 * 16];
    uint16_t wHi[16 * 0x490], wLo[16 * 0x490];
    for (int i = 0; i < 16; i++) init_nibble(hiA + i * 16);
    for (int i = 0; i < 256; i++) init_nibble(hiB + i * 16);
    for (int i = 0; i < 32; i++) init_nibble(loA + i * 16);
    for (int i = 0; i < 256; i++) init_nibble(loB + i * 16);
    for (int i = 0; i < 16 * 0x490; i++) wHi[i] = wLo[i] = 0x8000;
    int n = 0, prev = 0, esi = 0;
    for (; n < extraA && r.ok; n++) {
      int ha = (prev >> 4) & 15;
      int hb = prev & 255;
      int wix = ha * 0x490 + esi;
      int hi = get_nibble_mix(&r, hiA + ha * 16, hiB + hb * 16, &wHi[wix], 16, 6, kMatchTgt);
      if (hi < 0) break;
      int la = ctx_lo_pe(prev, hi);
      if (la < 0) la = 0;
      if (la > 31) la = 31;
      int lo = get_nibble_mix(&r, loA + la * 16, loB + hb * 16, &wLo[wix], 16, 7, kNibbleTgt);
      if (lo < 0) break;
      out[n] = (uint8_t)((hi << 4) | lo);
      prev = out[n];
      esi = kEsiTab[esi];
    }
    show_prefix("lzlit-win", out, n);
  }

  // 16-sym as dest bytes (raw / +0x20 / +0x30 / +0x40 / +0x5b) from window.
  {
    Rans r;
    win_rans(&r, 0);
    uint16_t cdf[16];
    init_nibble(cdf);
    int n = 0;
    int syms[32];
    for (; n < extraA && r.ok; n++) {
      int s = get_nibble(&r, cdf, 16, 5, kHdrTgt);
      if (s < 0) break;
      syms[n] = s;
      out[n] = (uint8_t)s;
    }
    show_prefix("sym-raw", out, n);
    for (int add = 0x20; add <= 0x5b; add += 0x0b) {
      for (int i = 0; i < n; i++) out[i] = (uint8_t)(syms[i] + add);
      char tag[32];
      snprintf(tag, sizeof(tag), "sym+%02x", add);
      show_prefix(tag, out, n);
    }
  }

  // decode_opt_int extraA times from window, low 8 bits.
  {
    Rans r;
    win_rans(&r, 0);
    ExtraModel A;
    extra_init(&A);
    int n = 0;
    for (; n < extraA && r.ok; n++) {
      int v = decode_opt_int(&r, &A, 1);
      if (v < 0) break;
      out[n] = (uint8_t)v;
    }
    show_prefix("b430-win", out, n);
  }
}

static void try_one(const uint8_t *src, int slen, int skip, int hdr, int opt_skip, int force_opt = -1) {
  if (skip + 4 > slen) return;
  uint8_t tmp[93116];
  int nsrc = slen - skip;
  if (nsrc > (int)sizeof(tmp)) nsrc = (int)sizeof(tmp);
  memcpy(tmp, src + skip, (size_t)nsrc);
  static uint8_t dst[430889];
  int n = decode_v22(tmp, nsrc, dst, (int)sizeof(dst), 1, hdr, opt_skip, force_opt);
  int pr = 0;
  for (int i = 0; i < n && i < 16; i++) {
    uint8_t c = dst[i];
    if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) pr++;
  }
  fprintf(stderr, "skip=%d hdr=%d opt=%d force=%d n=%d pr=%d first=", skip, hdr, opt_skip, force_opt, n, pr);
  for (int i = 0; i < n && i < 16; i++) fprintf(stderr, "%02x", dst[i]);
  if (n > 0) fprintf(stderr, " ascii=%.*s", n < 16 ? n : 16, dst);
  fprintf(stderr, "\n");
  if (n >= kEmu + kApp) {
    uint32_t c = crc32_ieee(dst + kEmu, kApp);
    fprintf(stderr, "  appid=%08x %s bytes=", c, c == kAppCRC ? "HIT" : "");
    for (int i = 0; i < kApp; i++) fprintf(stderr, "%02x", dst[kEmu + i]);
    fprintf(stderr, "\n");
    uint32_t ce = crc32_ieee(dst, kEmu);
    fprintf(stderr, "  emu=%08x %s\n", ce, ce == 0xfb362bfa ? "HIT" : "");
    if (c == kAppCRC || ce == 0xfb362bfa) {
      FILE *hf = fopen("/tmp/magic2-CRC-HIT.txt", "w");
      if (hf) {
        fprintf(hf, "HIT skip=%d hdr=%d opt_skip=%d force=%d n=%d app=%08x emu=%08x\n",
                skip, hdr, opt_skip, force_opt, n, c, ce);
        fclose(hf);
      }
    }
  }
}

int main(int argc, char **argv) {
  const char *path = argc > 1 ? argv[1]
                              : "/media/downloads/TORRENTS/RimWorld [FitGirl Repack]/fg-06.bin";
  FILE *f = fopen(path, "rb");
  if (!f) {
    perror(path);
    return 1;
  }
  if (fseek(f, 0x1F + 5, SEEK_SET) != 0) {
    perror("seek");
    return 1;
  }
  static uint8_t src[93116];
  int slen = (int)fread(src, 1, sizeof(src), f);
  fclose(f);
  int peeked = peek_opt(src, slen);
  fprintf(stderr, "peek_opt=%d extraA=%d extraB=%d hdroff=%d src0=%02x%02x%02x%02x\n", peeked, gExtraA, gExtraB,
          gHdrOff, src[0], src[1], src[2], src[3]);
  probe_fc5d_adapted(src, slen);
  probe_fc5d_window(src, slen);
  // steam_emu.ini is the first file member; prefix must be printable.
  // +0xc34 is only written from opt[+0x14] (0x14003b934); stream is not that blob.
  // 0x14006f513/0x14006f7ab sit past SizeOfImage — not in this PE.
  gCls11Mode = 6;
  {
    static uint8_t dump[430889];
    int n = decode_v22(src, slen, dump, (int)sizeof(dump), 1, 5, 0, -1);
    FILE *df = fopen("/tmp/m2-raw.bin", "wb");
    if (df) {
      fwrite(dump, 1, (size_t)n, df);
      fclose(df);
    }
    fprintf(stderr, "dumped hdr3 n=%d extraA=%d extraB=%d first=", n, gExtraA, gExtraB);
    for (int i = 0; i < n && i < 16; i++) fprintf(stderr, "%02x", dump[i]);
    if (n > 0) fprintf(stderr, " ascii=%.*s", n < 16 ? n : 16, dump);
    fprintf(stderr, "\n");
    try_one(src, slen, 0, 3, 0);
    try_one(src, slen, 0, 4, 0);
    try_one(src, slen, 0, 6, 0);
    try_one(src, slen, 0, 7, 0);
    try_one(src, slen, 0, 8, 0);
    try_one(src, slen, 0, 9, 0);
    try_one(src, slen, 0, 10, 0);
    try_one(src, slen, 0, 11, 0);
#ifdef HOST_DUMP_ONLY
    return n >= kEmu + kApp ? 0 : 2;
#endif
  }
  for (int skip = 0; skip <= 48; skip++) {
    try_one(src, slen, skip, 0, 0);
    try_one(src, slen, skip, 1, 0);
    try_one(src, slen, skip, 2, 0);
  }
  gCls11Mode = 3;
  for (int skip = 0; skip <= 32; skip += 2) try_one(src, slen, skip, 0, 0);
  return 2;
}
#endif
