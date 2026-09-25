// OGGRE write-as-we-go. 123b0 + unsigned 167c0 + 053cf/02790. No kWant pad.
// INV-03: PE is data only.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace {

const uint32_t kTop = 0x1000000u;
const uint32_t kWant = 255994514u;
const uint32_t kWantCRC = 0xf7a300d7u;
const uint32_t kDestCap = 300u << 20;

struct Range {
  uint32_t code, range;
  const uint8_t *ptr, *end;
  // 1bb0 window: 64KB buf, 081b0-style refill from backing src.
  uint8_t *win;
  uint32_t win_cap;
  const uint8_t *src, *src_end;
  int err;
};

static int win_refill(Range *r) {
  if (!r->win || !r->src || r->src >= r->src_end) return -1;
  uint32_t n = r->win_cap;
  uint32_t have = (uint32_t)(r->src_end - r->src);
  if (n > have) n = have;
  if (n == 0) return -1;
  memcpy(r->win, r->src, n);
  r->src += n;
  r->ptr = r->win;
  r->end = r->win + n;
  return 0;
}

static int refill(Range *r) {
  while (r->range < kTop) {
    if (r->ptr >= r->end) {
      if (win_refill(r) < 0) return -1;
    }
    r->code = (r->code << 8) | *r->ptr++;
    r->range <<= 8;
  }
  return 0;
}

// 1bb0: pxor this+4, malloc 0x10000, pack 4 window bytes into code, range=-1.
static int range_init_window(Range *r, const uint8_t *src, uint32_t slen, uint32_t off) {
  memset(r, 0, sizeof(*r));
  r->win_cap = 0x10000;
  r->win = (uint8_t *)malloc(r->win_cap);
  if (!r->win) return -1;
  if (off >= slen) return -1;
  r->src = src + off;
  r->src_end = src + slen;
  if (win_refill(r) < 0) return -1;
  r->code = 0;
  r->range = 0xffffffffu;
  for (int i = 0; i < 4; i++) {
    if (r->ptr >= r->end && win_refill(r) < 0) return -1;
    r->code = (r->code << 8) | *r->ptr++;
  }
  return 0;
}

static int getbit(Range *r, uint16_t *freq) {
  if (r->err) return -1;
  if (refill(r) < 0) {
    r->err = 1;
    return -1;
  }
  uint32_t range = r->range, code = r->code, f = *freq;
  uint32_t bound = (range >> 16) * f;
  if (code >= bound) {
    r->code = code - bound;
    r->range = range - bound;
    *freq = (uint16_t)(f - (f >> 6));
    return 1;
  }
  r->range = bound;
  *freq = (uint16_t)(f + ((0xffffu - f) >> 6));
  return 0;
}

static void init_freq(uint16_t *p, uint32_t n) {
  for (uint32_t i = 0; i < n; i++) p[i] = 0x8000;
}

static uint32_t gCrcTab[256];
static void crc_init(void) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t r = i << 24;
    for (int j = 0; j < 8; j++)
      r = (r & 0x80000000u) ? (r << 1) ^ 0x04c11db7u : (r << 1);
    gCrcTab[i] = r;
  }
}
static void put_le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}
static void put_le64(uint8_t *p, uint64_t v) {
  put_le32(p, (uint32_t)v);
  put_le32(p + 4, (uint32_t)(v >> 32));
}

// 15c20: signed 2-bit tree + extra_same (channels).
static int range_dec_signed_2(Range *rc, uint8_t *slot, int extra_sel) {
  int ctx = slot[0x08];
  int bit = getbit(rc, (uint16_t *)(slot + 0x0c + 2 * ctx));
  if (bit < 0) return 0x80000000;
  slot[0x08] = (uint8_t)((bit + 2 * ctx) & 3);
  if (bit == 0) {
    slot[0x0a] = 0;
    return 0;
  }
  int sign = getbit(rc, (uint16_t *)(slot + 0x14 + 2 * slot[0x09]));
  if (sign < 0) return 0x80000000;
  slot[0x09] = (uint8_t)(sign & 1);
  uint8_t *node = slot + 0x34 + ((int)slot[0x0a] << 3);
  bit = getbit(rc, (uint16_t *)(node + 2));
  if (bit < 0) return 0x80000000;
  int v = 4 + 2 * bit;
  bit = getbit(rc, (uint16_t *)(node + v));
  if (bit < 0) return 0x80000000;
  int n = (v + bit) & 3;
  slot[0x0a] = (uint8_t)(n + 1);
  uint8_t *base = extra_sel ? slot + 0x834 + (n << 2) : slot + 0x834;
  int extra = 1;
  for (int i = 0; i < n; i++) {
    bit = getbit(rc, (uint16_t *)(base + 2));
    if (bit < 0) return 0x80000000;
    extra = bit + 2 * extra;
  }
  return (extra ^ -sign) + sign;
}

// PE 0x100123b0 signed 3-bit tree + extra_walk (always sign).
static int range_dec_signed_3(Range *rc, uint8_t *slot, int extra_sel) {
  int ctx = slot[0x08];
  int bit = getbit(rc, (uint16_t *)(slot + 0x0c + 2 * ctx));
  if (bit < 0) return 0x80000000;
  slot[0x08] = (uint8_t)((bit + 2 * ctx) & 3);
  if (bit == 0) {
    slot[0x0a] = 0;
    return 0;
  }
  int sign = getbit(rc, (uint16_t *)(slot + 0x14 + 2 * slot[0x09]));
  if (sign < 0) return 0x80000000;
  slot[0x09] = (uint8_t)(sign & 1);
  uint8_t *node = slot + 0x34 + ((int)slot[0x0a] << 4);
  bit = getbit(rc, (uint16_t *)(node + 2));
  if (bit < 0) return 0x80000000;
  int v = 4 + 2 * bit;
  bit = getbit(rc, (uint16_t *)(node + v));
  if (bit < 0) return 0x80000000;
  v = v + bit;
  bit = getbit(rc, (uint16_t *)(node + 2 * v));
  if (bit < 0) return 0x80000000;
  int n = (bit + 2 * v) & 7;
  slot[0x0a] = (uint8_t)(n + 1);
  uint8_t *base = extra_sel ? slot + 0x834 + (n << 5) : slot + 0x834;
  int extra = 1;
  if (n > 0) {
    bit = getbit(rc, (uint16_t *)(base + 2));
    if (bit < 0) return 0x80000000;
    extra = bit + 2;
    int si = (2 + bit) & 15;
    for (int i = 1; i < n; i++) {
      bit = getbit(rc, (uint16_t *)(base + 2 * si));
      if (bit < 0) return 0x80000000;
      extra = bit + 2 * extra;
      if (si < 8) si = (2 * si + bit) & 15;
    }
  }
  return (extra ^ -sign) + sign;
}

// 15260: signed 5-bit tree + extra_walk (rate / bitrate).
static int range_dec_signed_5(Range *rc, uint8_t *slot, int extra_sel) {
  int ctx = slot[0x08];
  int bit = getbit(rc, (uint16_t *)(slot + 0x0c + 2 * ctx));
  if (bit < 0) return 0x80000000;
  slot[0x08] = (uint8_t)((bit + 2 * ctx) & 3);
  if (bit == 0) {
    slot[0x0a] = 0;
    return 0;
  }
  int sign = getbit(rc, (uint16_t *)(slot + 0x14 + 2 * slot[0x09]));
  if (sign < 0) return 0x80000000;
  slot[0x09] = (uint8_t)(sign & 1);
  uint8_t *node = slot + 0x34 + ((int)slot[0x0a] << 6);
  bit = getbit(rc, (uint16_t *)(node + 2));
  if (bit < 0) return 0x80000000;
  int v = 4 + 2 * bit;
  bit = getbit(rc, (uint16_t *)(node + v));
  if (bit < 0) return 0x80000000;
  v = v + bit;
  for (int i = 0; i < 3; i++) {
    bit = getbit(rc, (uint16_t *)(node + 2 * v));
    if (bit < 0) return 0x80000000;
    v = bit + 2 * v;
  }
  int n = v & 31;
  slot[0x0a] = (uint8_t)(n + 1);
  uint8_t *base = extra_sel ? slot + 0x834 + (n << 5) : slot + 0x834;
  int extra = 1;
  if (n > 0) {
    bit = getbit(rc, (uint16_t *)(base + 2));
    if (bit < 0) return 0x80000000;
    extra = bit + 2;
    int si = (2 + bit) & 15;
    for (int i = 1; i < n; i++) {
      bit = getbit(rc, (uint16_t *)(base + 2 * si));
      if (bit < 0) return 0x80000000;
      extra = bit + 2 * extra;
      if (si < 8) si = (2 * si + bit) & 15;
    }
  }
  return (extra ^ -sign) + sign;
}

// unsigned 3-bit tree + extra_walk (167c0 npackets).
static int dec_npackets(Range *rc, uint8_t *slot) {
  int ctx = slot[0x08];
  int bit = getbit(rc, (uint16_t *)(slot + 0x0c + 2 * ctx));
  if (bit < 0) return -1;
  slot[0x08] = (uint8_t)((bit + 2 * ctx) & 3);
  if (bit == 0) {
    slot[0x0a] = 0;
    return 0;
  }
  uint8_t *node = slot + 0x34 + ((int)slot[0x0a] << 4);
  bit = getbit(rc, (uint16_t *)(node + 2));
  if (bit < 0) return -1;
  int v = 4 + 2 * bit;
  bit = getbit(rc, (uint16_t *)(node + v));
  if (bit < 0) return -1;
  v = v + bit;
  bit = getbit(rc, (uint16_t *)(node + 2 * v));
  if (bit < 0) return -1;
  int n = (bit + 2 * v) & 7;
  slot[0x0a] = (uint8_t)(n + 1);
  uint8_t *base = slot + 0x834 + (n << 5);
  int extra = 1;
  if (n > 0) {
    bit = getbit(rc, (uint16_t *)(base + 2));
    if (bit < 0) return -1;
    extra = bit + 2;
    int si = (2 + bit) & 15;
    for (int i = 1; i < n; i++) {
      bit = getbit(rc, (uint16_t *)(base + 2 * si));
      if (bit < 0) return -1;
      extra = bit + 2 * extra;
      if (si < 8) si = (2 * si + bit) & 15;
    }
  }
  return extra;
}

// unsigned 4-bit tree + extra_walk (167c0 packet size).
static int dec_packet_size(Range *rc, uint8_t *slot) {
  int ctx = slot[0x08];
  int bit = getbit(rc, (uint16_t *)(slot + 0x0c + 2 * ctx));
  if (bit < 0) return -1;
  slot[0x08] = (uint8_t)((bit + 2 * ctx) & 3);
  if (bit == 0) {
    slot[0x0a] = 0;
    return 0;
  }
  uint8_t *node = slot + 0x34 + ((int)slot[0x0a] << 5);
  bit = getbit(rc, (uint16_t *)(node + 2));
  if (bit < 0) return -1;
  int v = 4 + 2 * bit;
  bit = getbit(rc, (uint16_t *)(node + v));
  if (bit < 0) return -1;
  v = v + bit;
  bit = getbit(rc, (uint16_t *)(node + 2 * v));
  if (bit < 0) return -1;
  v = bit + 2 * v;
  bit = getbit(rc, (uint16_t *)(node + 2 * v));
  if (bit < 0) return -1;
  int n = (bit + 2 * v) & 15;
  slot[0x0a] = (uint8_t)(n + 1);
  int extra = 1;
  if (n > 0) {
    uint8_t *base = slot + 0x834 + (n << 7);
    int si = 1;
    for (int i = 0; i < n; i++) {
      bit = getbit(rc, (uint16_t *)(base + 2 * si));
      if (bit < 0) return -1;
      extra = bit + 2 * extra;
      if (si < 32) si = (2 * si + bit) & 63;
    }
  }
  return extra;
}

// 0xc870: signed 4-bit tree + extra_walk (dim). extra mask=15 cap=8.
static int range_dec_signed_4(Range *rc, uint8_t *slot) {
  int ctx = slot[0x08];
  int bit = getbit(rc, (uint16_t *)(slot + 0x0c + 2 * ctx));
  if (bit < 0) return 0x80000000;
  slot[0x08] = (uint8_t)((bit + 2 * ctx) & 3);
  if (bit == 0) {
    slot[0x0a] = 0;
    return 0;
  }
  int sign = getbit(rc, (uint16_t *)(slot + 0x14 + 2 * slot[0x09]));
  if (sign < 0) return 0x80000000;
  slot[0x09] = (uint8_t)(sign & 1);
  uint8_t *node = slot + 0x34 + ((int)slot[0x0a] << 5);
  bit = getbit(rc, (uint16_t *)(node + 2));
  if (bit < 0) return 0x80000000;
  int v = 4 + 2 * bit;
  bit = getbit(rc, (uint16_t *)(node + v));
  if (bit < 0) return 0x80000000;
  v = v + bit;
  bit = getbit(rc, (uint16_t *)(node + 2 * v));
  if (bit < 0) return 0x80000000;
  v = bit + 2 * v;
  bit = getbit(rc, (uint16_t *)(node + 2 * v));
  if (bit < 0) return 0x80000000;
  int n = (bit + 2 * v) & 15;
  slot[0x0a] = (uint8_t)(n + 1);
  uint8_t *base = slot + 0x834;
  int extra = 1;
  if (n > 0) {
    bit = getbit(rc, (uint16_t *)(base + 2));
    if (bit < 0) return 0x80000000;
    extra = bit + 2;
    int si = (2 + bit) & 15;
    for (int i = 1; i < n; i++) {
      bit = getbit(rc, (uint16_t *)(base + 2 * si));
      if (bit < 0) return 0x80000000;
      extra = bit + 2 * extra;
      if (si < 8) si = (2 * si + bit) & 15;
    }
  }
  return (extra ^ -sign) + sign;
}

// 0xbe70: unsigned 5-bit tree + extra_walk mask=63 (ent).
static int range_dec_u5_wide(Range *rc, uint8_t *slot) {
  int ctx = slot[0x08];
  int bit = getbit(rc, (uint16_t *)(slot + 0x0c + 2 * ctx));
  if (bit < 0) return -1;
  slot[0x08] = (uint8_t)((bit + 2 * ctx) & 3);
  if (bit == 0) {
    slot[0x0a] = 0;
    return 0;
  }
  uint8_t *node = slot + 0x34 + ((int)slot[0x0a] << 6);
  bit = getbit(rc, (uint16_t *)(node + 2));
  if (bit < 0) return -1;
  int v = 4 + 2 * bit;
  bit = getbit(rc, (uint16_t *)(node + v));
  if (bit < 0) return -1;
  v = v + bit;
  for (int i = 0; i < 3; i++) {
    bit = getbit(rc, (uint16_t *)(node + 2 * v));
    if (bit < 0) return -1;
    v = bit + 2 * v;
  }
  int n = v & 31;
  slot[0x0a] = (uint8_t)(n + 1);
  int extra = 1;
  if (n > 0) {
    uint8_t *base = slot + 0x834 + (n << 6);
    bit = getbit(rc, (uint16_t *)(base + 2));
    if (bit < 0) return -1;
    extra = bit + 2;
    int si = (2 + bit) & 63;
    for (int i = 1; i < n; i++) {
      bit = getbit(rc, (uint16_t *)(base + 2 * si));
      if (bit < 0) return -1;
      extra = bit + 2 * extra;
      if (si < 32) si = (2 * si + bit) & 63;
    }
  }
  return extra;
}

static int vorbis_ilog(uint32_t v) {
  int n = 0;
  while (v) {
    n++;
    v >>= 1;
  }
  return n;
}

// HOST ELF BitBuf / Books / AudioSt (decode_02790 + write_book).
struct BitBuf {
  uint8_t *p;
  int cap, used, bit;
};

struct BookEnt {
  int entries, dim, nbits;
  uint8_t *len;
  uint32_t *code;
};

struct Books {
  BookEnt *tab;
  int n;
};

struct AudioSt {
  uint8_t *mem;
  uint32_t memsz;
  uint8_t ctx14;
  uint8_t res_ctx[0x900];
  Books books;
  uint8_t npart;
  uint8_t part_class[32];
  int16_t cascade[16][8];
  uint8_t dimc[16];
  uint8_t bitsc[16];
  uint8_t classbook[16];
  int16_t class_vals[16][8];
  uint8_t floor_mult;
  int floor_nvals;
  uint8_t xlist[65];
  int ready;
  int nmodes;
  int mode;
  int first_done;
  int nch;
  // Setup residue (PE 053cf). Type-0 floor skips Y only; residue still writes.
  uint8_t res_ok;
  uint8_t res_type;
  uint8_t res_ncl;
  uint8_t res_classbook;
  int res_begin;
  int res_end;
  int res_psize;
  int res_cascade[16];
  int16_t res_books[16][8];
};

#ifdef HOST_DEBUG
static uint64_t gWbCalls, gWbBits, gWbNz, gResRun, gBit1;
#endif

static const uint32_t kFloorRange[6] = {255, 127, 85, 63, 63, 63};

// One type-1 floor from setup. 02790 uses the mapping's floor, not max/capped 65.
struct FloorRec {
  uint8_t ok;
  uint8_t mult;
  uint8_t npart;
  int nvals;
  uint8_t xlist[65];
  uint8_t pclass[32];
  uint8_t dimc[16];
  uint8_t bitsc[16];
  uint8_t cbook[16];
  int16_t sub[16][8];
};

// One residue from setup (PE 053cf after floors). ncl/cascade/books, not floor parts.
struct ResidueRec {
  uint8_t ok;
  uint8_t type;
  uint8_t ncl;
  uint8_t classbook;
  int begin;
  int end;
  int psize;
  int cascade[16];
  int16_t books[16][8];
};

static int write_bits(BitBuf *b, uint32_t v, int n) {
  if (n <= 0) return 0;
  if (!b || !b->p) return -1;
  for (int i = 0; i < n; i++) {
    if (b->used >= b->cap) return -1;
    b->p[b->used] |= (uint8_t)(((v >> i) & 1u) << b->bit);
    b->bit++;
    if (b->bit == 8) {
      b->bit = 0;
      b->used++;
    }
  }
  return 0;
}

static void book_build(BookEnt *b) {
  if (!b || b->entries <= 0 || !b->len) {
    if (b) b->nbits = vorbis_ilog((uint32_t)(b && b->entries > 0 ? b->entries : 1));
    return;
  }
  int e = b->entries;
  b->code = (uint32_t *)calloc((size_t)e, sizeof(uint32_t));
  if (!b->code) return;
  uint32_t code = 0;
  int any = 0;
  for (int len = 1; len <= 32; len++) {
    for (int i = 0; i < e; i++) {
      if (b->len[i] == (uint8_t)len) {
        b->code[i] = code;
        code++;
        any = 1;
      }
    }
    code <<= 1;
  }
  b->nbits = vorbis_ilog((uint32_t)e);
  if (b->nbits < 1) b->nbits = 1;
  if (!any) {
    free(b->code);
    b->code = 0;
  }
}

static void books_free(Books *bs) {
  if (!bs || !bs->tab) return;
  for (int i = 0; i < bs->n; i++) {
    free(bs->tab[i].len);
    free(bs->tab[i].code);
  }
  free(bs->tab);
  bs->tab = 0;
  bs->n = 0;
}

#ifdef HOST_DEBUG
static int write_book_count(BitBuf *bb, const Books *bs, int book_idx, int value) {
  int before_used = bb ? bb->used : 0;
  int before_bit = bb ? bb->bit : 0;
  int rc = 0;
#else
static int write_book(BitBuf *bb, const Books *bs, int book_idx, int value) {
#endif
  // PE 02790: 2108*book_id, nbits=signed len[value]. Unused len is 0, not 32.
  // 8-bit book indexes are 0..nbooks-1; do not wrap (19%6) or treat cascade as an id.
  if (!bs || bs->n <= 0 || !bs->tab) return 0;
  if (book_idx < 0 || book_idx >= bs->n) {
#ifdef HOST_DEBUG
    gWbCalls++;
    if (gWbCalls <= 8)
      fprintf(stderr, "  wb#%llu book=%d val=%d nbits=0 code=0 skip=range used=%d->%d bit=%d->%d\n",
              (unsigned long long)gWbCalls, book_idx, value, before_used, bb ? bb->used : 0,
              before_bit, bb ? bb->bit : 0);
#endif
    return 0;
  }
  const BookEnt *b = &bs->tab[book_idx];
  int entries = b->entries > 0 ? b->entries : 1;
  int val = value;
  // PE write_book indexes len[value] after masking the 038c0 residue
  // symbol onto the book alphabet. Do not skip out-of-range vals.
  if (val < 0) val = 0;
  if (val >= entries) val %= entries;
#ifdef HOST_DEBUG
  int nbits_w = 0;
  uint32_t code_w = 0;
#endif
  int wr = 0;
  int nbits = (b->len) ? (int)b->len[val] : 0;
  if (nbits < 1 || nbits > 32) {
#ifdef HOST_DEBUG
    gWbCalls++;
    if (gWbCalls <= 8)
      fprintf(stderr, "  wb#%llu book=%d val=%d nbits=0 code=0 skip=unused used=%d->%d bit=%d->%d\n",
              (unsigned long long)gWbCalls, book_idx, val, before_used, bb ? bb->used : 0,
              before_bit, bb ? bb->bit : 0);
#endif
    return 0;
  }
  uint32_t code = b->code ? b->code[val] : (uint32_t)val;
#ifdef HOST_DEBUG
  nbits_w = nbits;
  code_w = code;
#endif
  wr = write_bits(bb, code, nbits);
#ifdef HOST_DEBUG
  gWbCalls++;
  gWbBits += (uint64_t)nbits_w;
  if (code_w) gWbNz++;
  if (gWbCalls <= 8) {
    if (value != val)
      fprintf(stderr, "  wb#%llu book=%d val=%d nbits=%d code=%u used=%d->%d bit=%d->%d raw=%d\n",
              (unsigned long long)gWbCalls, book_idx, val, nbits_w, code_w, before_used, bb ? bb->used : 0,
              before_bit, bb ? bb->bit : 0, value);
    else
      fprintf(stderr, "  wb#%llu book=%d val=%d nbits=%d code=%u used=%d->%d bit=%d->%d\n",
              (unsigned long long)gWbCalls, book_idx, val, nbits_w, code_w, before_used, bb ? bb->used : 0,
              before_bit, bb ? bb->bit : 0);
  }
  rc = wr;
  return rc;
#else
  return wr;
#endif
}

#ifdef HOST_DEBUG
static int write_book(BitBuf *bb, const Books *bs, int book_idx, int value) {
  return write_book_count(bb, bs, book_idx, value);
}
#endif

static uint16_t *freq_at(uint8_t *mem, uint32_t memsz, uint32_t off);

static int book_entries(const Books *bs, int book_idx) {
  if (!bs || !bs->tab || bs->n <= 0) return 1;
  if (book_idx < 0 || book_idx >= bs->n) return 1;
  int e = bs->tab[book_idx].entries;
  return e > 0 ? e : 1;
}

static int y_at(const int16_t *Y, int i) {
  if (!Y || i < 0 || i >= 65) return 0;
  return (int)Y[i];
}

// PE 02790 getbit tree (038c0): present flag + 3-bit n + extra. Floor Y uses
// xlist[i]; type-0 residue uses the book id as x. Same slots as the Y loop.
static int decode_sym_tree(Range *r, AudioSt *st, int x, int mode_lo, int *fctx, int max_nb) {
  if (!r || !st || !st->mem) return 0;
  uint8_t *mem = st->mem;
  uint32_t memsz = st->memsz;
  int ctx = fctx ? (*fctx & 3) : 0;
  int gbit = 0;
  int xx = x;
  if ((unsigned)xx > 0x40) {
    xx = 0;
  } else {
    uint32_t off = (uint32_t)(0x225c + 4 * xx + (ctx << 7) + mode_lo) * 2;
    uint16_t *f = freq_at(mem, memsz, off);
    if (!f) return 0;
    gbit = getbit(r, f);
    if (gbit < 0) return 0;
  }
  uint32_t r11 = ((uint32_t)mode_lo << 8) + (uint32_t)xx;
  if (r11 >= 0x900) r11 = 0;
  int yv = 0;
  int nb_store = 0;
  if (gbit != 0) {
    int prev = st->res_ctx[r11] & 7;
    int node = ((((prev << 5) + xx) << 6) + (mode_lo << 4));
    uint16_t *f0 = freq_at(mem, memsz, (uint32_t)(0x244ba + node));
    if (!f0) return 0;
    int b0 = getbit(r, f0);
    if (b0 < 0) return 0;
    int v = 4 + 2 * b0;
    uint16_t *f1 = freq_at(mem, memsz, (uint32_t)(0x244b8 + node + v));
    if (!f1) return 0;
    int b1 = getbit(r, f1);
    if (b1 < 0) return 0;
    v = v + b1;
    uint16_t *f2 = freq_at(mem, memsz, (uint32_t)(0x244b8 + node + 2 * v));
    if (!f2) return 0;
    int b2 = getbit(r, f2);
    if (b2 < 0) return 0;
    int nb = (b2 + 2 * v) & 7;
    if (max_nb > 0 && nb > max_nb) nb = max_nb;
    nb_store = nb;
    if (nb == 0) {
      yv = 1;
    } else {
      int extra = 1;
      int bctx = 0;
      int r10 = 0;
      int stop = -4 * nb;
      int base = nb * 0x108 + (xx << 14) + (mode_lo << 6) - 8;
      while (r10 != stop) {
        uint32_t off = (uint32_t)(0x444b8 + base + 2 * (r10 + bctx));
        uint16_t *fe = freq_at(mem, memsz, off);
        if (!fe) return 0;
        int b = getbit(r, fe);
        if (b < 0) return 0;
        extra = b + 2 * extra;
        bctx = (b + 2 * bctx) & 3;
        r10 -= 4;
      }
      yv = extra;
    }
  }
  if (fctx) *fctx = (gbit + 2 * ctx) & 3;
  st->res_ctx[r11] = (uint8_t)(gbit == 0 ? 0 : (nb_store & 7));
  return yv;
}

// Type-0 floor has no Y[]. Residue class/book symbols are the 038c0 tree.
static int decode_rsym(Range *r, AudioSt *st, int book_idx, int mode_lo, int *fctx) {
  int x = book_idx;
  if (x < 0) x = 0;
  if (x > 0x40) x = 0x40;
  return decode_sym_tree(r, st, x, mode_lo, fctx, 0);
}

// PE 02790 02f84–033be: per partition, class dim, cascade/sub books.
// Type-1: value is floor Y[val_index]. Type-0: range-decode class/book (038c0).
// Floor npart at *(uint8_t*)floor; type-0 is 0 so residue npart is used.
static int write_residue(AudioSt *st, BitBuf *bb, const int16_t *Y, Range *r, int mode_lo) {
  if (!bb || !st) return 0;
  int floor_npart = st->npart;
  int grouping = st->res_psize;
  if (grouping < 1) grouping = 1;
  int res_npart = 0;
  if (st->res_end > st->res_begin) res_npart = (st->res_end - st->res_begin) / grouping;
  int npart = floor_npart > 0 ? floor_npart : res_npart;
  if (npart <= 0) return 0;
  if (npart > 128) npart = 128;
#ifdef HOST_DEBUG
  gResRun++;
#endif
  int ncl = st->res_ncl;
  if (ncl <= 0) ncl = 1;
  if (ncl > 16) ncl = 16;
  int use_floor = floor_npart > 0;
  // PE val_index starts at 2 (Y[0]/Y[1] already written at 02bb9).
  int val_index = 2;
  int fctx = 0;
  for (int p = 1; p <= npart; p++) {
    int cls, dim, bits, cbook;
    int stage_books[8];
    int nstage = 0;
    if (use_floor) {
      cls = (p < 32) ? (st->part_class[p] & 15) : 0;
      dim = st->dimc[cls];
      bits = st->bitsc[cls] & 7;
      cbook = st->classbook[cls];
      if (dim < 0) dim = 0;
      if (dim > 16) dim = 16;
    } else {
      cls = (p - 1) % ncl;
      bits = 0;
      cbook = st->res_classbook;
      if (r) {
        int csym = decode_rsym(r, st, cbook, mode_lo, &fctx);
        if (write_book(bb, &st->books, cbook, csym) < 0) return -1;
        if (ncl > 0) {
          int c = csym % ncl;
          if (c < 0) c += ncl;
          cls = c;
        }
      }
      // Cascade bits only: one write_book per set stage, not book.dim/nvec.
      for (int s = 0; s < 8; s++) {
        if (!(st->res_cascade[cls] & (1 << s))) continue;
        int bi = st->res_books[cls][s];
        if (bi < 0) continue;
        if (nstage < 8) stage_books[nstage++] = bi;
      }
      dim = nstage;
    }
    int digits[16];
    memset(digits, 0, sizeof(digits));
    if (use_floor && bits) {
      int nsub = 1 << bits;
      if (nsub > 8) nsub = 8;
      int thresh[8];
      for (int d = 0; d < nsub; d++) {
        int bi = st->cascade[cls][d];
        thresh[d] = (bi >= 0) ? book_entries(&st->books, bi) : 1;
      }
      int packed = 0;
      int shift = 0;
      for (int i = 0; i < dim && i < 16; i++) {
        int yv = y_at(Y, val_index + i);
        int digit = nsub > 0 ? nsub - 1 : 0;
        for (int d = 0; d < nsub; d++) {
          if (yv < thresh[d]) {
            digit = d;
            break;
          }
        }
        digits[i] = digit;
        packed |= digit << shift;
        shift += bits;
      }
      if (write_book(bb, &st->books, cbook, packed) < 0) return -1;
    }
    if (dim <= 0) continue;
    for (int i = 0; i < dim; i++) {
      int bi;
      if (use_floor) {
        int digit = bits ? digits[i] : 0;
        if (digit < 0) digit = 0;
        if (digit > 7) digit = 7;
        bi = st->cascade[cls][digit];
      } else {
        bi = stage_books[i];
      }
      if (bi < 0) continue;
      int val = use_floor ? y_at(Y, val_index + i) : decode_rsym(r, st, bi, mode_lo, &fctx);
      if (write_book(bb, &st->books, bi, val) < 0) return -1;
    }
    val_index += dim;
  }
  return 0;
}

static uint16_t *freq_at(uint8_t *mem, uint32_t memsz, uint32_t off) {
  if (!mem) return 0;
  if (memsz <= 3) return (uint16_t *)mem;
  if (off + 2 > memsz) off = 0x44aa;
  return (uint16_t *)(mem + off);
}

// HOST ELF decode_02790: packet-type 0 + 0x44aa flag + floor/residue write_book.
static int decode_02790(Range *r, AudioSt *st, BitBuf *bb, int nch) {
  if (nch <= 0) return 1;
  if (!st || !st->ready) return -1;
  int reuse = st->first_done && bb->used && (bb->bit + bb->used * 8 - 8) != 0;
  int mode = st->mode;
  if (!reuse) {
    // Body packets are always audio; PE does not range-decode this bit.
    if (write_bits(bb, 0, 1) < 0) return -1;
    // nmodes=1 ⇒ ilog(nmodes-1)=0. Extra mode bits only when nmodes>1.
    int nmodes = st->nmodes;
    int mb = 0;
    if (nmodes > 1) mb = vorbis_ilog((uint32_t)(nmodes - 1));
    uint32_t extra = 0;
    uint8_t *model = st->mem;
    for (int i = 0; i < mb && model; i++) {
      int ctx = st->ctx14 & 3;
      uint16_t *fp = freq_at(model, st->memsz, 0x44aa + 2 * (uint32_t)ctx);
      if (!fp) return -1;
      int bit = getbit(r, fp);
      if (bit < 0) return -1;
      st->ctx14 = (uint8_t)((bit + 2 * ctx) & 3);
      extra |= (uint32_t)bit << i;
    }
    if (mb > 0 && write_bits(bb, extra, mb) < 0) return -1;
    mode = (int)extra;
    st->mode = mode;
    st->first_done = 1;
  }

  int nloop = nch < 8 ? nch : 8;
  int mode_lo = mode & 7;
  uint8_t *mem = st->mem;
  uint32_t memsz = st->memsz;

  for (int ch = 0; ch < nloop; ch++) {
    int ctx = st->ctx14 & 3;
    uint16_t *fp = freq_at(mem, memsz, 0x44aa + 2 * (uint32_t)ctx);
    if (!fp) return -1;
    int bit = getbit(r, fp);
    if (bit < 0) return -1;
    // 0x44aa is OGGRE's coded-channel flag. Vorbis has no such bit
    // after the packet type; do not write it. Still use it to skip Y.
    st->ctx14 = (uint8_t)((bit + 2 * ctx) & 3);
    if (bit == 0) continue;

    int16_t Y[65];
    memset(Y, 0, sizeof(Y));
    int nvals = st->floor_nvals;
    // PE 02bb9 always writes Y[0]/Y[1]. Type-0 nvals=0 still runs two
    // amplitude slots (xlist[0]=0, [1]=1) before 02f84 skips residue.
    if (nvals < 2) nvals = 2;
    {
      int n = nvals < 65 ? nvals : 65;
      int fctx = 0;
      for (int i = 0; i < n; i++) {
        int x = st->xlist[i];
        int gbit = 0;
        if ((unsigned)x > 0x40) {
          x = 0;
        } else {
          uint32_t off = (uint32_t)(0x225c + 4 * x + (fctx << 7) + mode_lo) * 2;
          uint16_t *f = freq_at(mem, memsz, off);
          if (!f) return -1;
          gbit = getbit(r, f);
          if (gbit < 0) return -1;
        }
        uint32_t r11 = ((uint32_t)mode_lo << 8) + (uint32_t)x;
        if (r11 >= 0x900) r11 = 0;
        int yv = 0;
        int nb_store = 0;
        if (gbit != 0) {
          int prev = st->res_ctx[r11] & 7;
          int node = ((((prev << 5) + x) << 6) + (mode_lo << 4));
          uint16_t *f0 = freq_at(mem, memsz, (uint32_t)(0x244ba + node));
          if (!f0) return -1;
          int b0 = getbit(r, f0);
          if (b0 < 0) return -1;
          int v = 4 + 2 * b0;
          uint16_t *f1 = freq_at(mem, memsz, (uint32_t)(0x244b8 + node + v));
          if (!f1) return -1;
          int b1 = getbit(r, f1);
          if (b1 < 0) return -1;
          v = v + b1;
          uint16_t *f2 = freq_at(mem, memsz, (uint32_t)(0x244b8 + node + 2 * v));
          if (!f2) return -1;
          int b2 = getbit(r, f2);
          if (b2 < 0) return -1;
          int nb = (b2 + 2 * v) & 7;
          nb_store = nb;
          if (nb == 0) {
            yv = 1;
          } else {
            int extra = 1;
            int bctx = 0;
            int r10 = 0;
            int stop = -4 * nb;
            int base = nb * 0x108 + (x << 14) + (mode_lo << 6) - 8;
            while (r10 != stop) {
              uint32_t off = (uint32_t)(0x444b8 + base + 2 * (r10 + bctx));
              uint16_t *fe = freq_at(mem, memsz, off);
              if (!fe) return -1;
              int b = getbit(r, fe);
              if (b < 0) return -1;
              extra = b + 2 * extra;
              bctx = (b + 2 * bctx) & 3;
              r10 -= 4;
            }
            yv = extra;
          }
        }
        fctx = (gbit + 2 * fctx) & 3;
        st->res_ctx[r11] = (uint8_t)(gbit == 0 ? 0 : (nb_store & 7));
        if (x >= 0 && x < 65) Y[x] = (int16_t)yv;
      }
    }

    // Type-0 floor: skip Y decode. PE 02bb9 still writes Y[0]/Y[1].
    int ybits = 8;
    {
      int mi = st->floor_mult;
      if (mi > 5) mi = 5;
      uint32_t rng = kFloorRange[mi];
      ybits = vorbis_ilog(rng);
      if (ybits < 1) ybits = 1;
      uint32_t mask = ybits >= 32 ? 0xffffffffu : ((1u << ybits) - 1);
      if (write_bits(bb, (uint32_t)Y[0] & mask, ybits) < 0) return -1;
      if (write_bits(bb, (uint32_t)Y[1] & mask, ybits) < 0) return -1;
    }
#ifdef HOST_DEBUG
    gBit1++;
    if (gBit1 <= 4)
      fprintf(stderr, "  y0=%d y1=%d nvals=%d npart=%d ybits=%d pkt=%d:%02x%02x%02x%02x\n",
              (int)Y[0], (int)Y[1], nvals, st->npart, ybits, bb->used, bb->p[0], bb->p[1], bb->p[2],
              bb->p[3]);
#endif
    // PE 02f84: type-0 npart=0 skips residue.
    if (st->npart > 0) {
      if (write_residue(st, bb, Y, r, mode_lo) < 0) return -1;
    }
  }
  return 0;
}

// One 02790 packet. Overflow continues into the next dest (03690); leftover dest stays 0.
struct PktStream {
  uint8_t buf[4096];
  int len, off;
};

static int emit_02790_dest(Range *r, AudioSt *st, PktStream *ps, uint8_t *out, int n, int nch,
                           int allow_new) {
  if (n <= 0 || !ps) return 0;
  if (ps->off >= ps->len) {
    if (!allow_new) return 0;
    memset(ps->buf, 0, sizeof(ps->buf));
    BitBuf bb = {ps->buf, (int)sizeof(ps->buf), 0, 0};
    decode_02790(r, st, &bb, nch);
    ps->len = bb.used + (bb.bit ? 1 : 0);
    ps->off = 0;
  }
  if (ps->len <= 0) return 0;
  int take = n;
  if (take > ps->len - ps->off) take = ps->len - ps->off;
  if (take > 0) memcpy(out, ps->buf + ps->off, (size_t)take);
  ps->off += take;
  if (ps->off >= ps->len) {
    ps->len = 0;
    ps->off = 0;
  }
  return take;
}

struct Writer {
  uint8_t *dst;
  uint32_t cap, pos;
};

static int emit(Writer *w, const uint8_t *p, uint32_t n) {
  if (w->pos >= w->cap) return -1;
  if (n > w->cap - w->pos) n = w->cap - w->pos;
  if (n && p) memcpy(w->dst + w->pos, p, n);
  w->pos += n;
  return (int)n;
}

static int emit_page(Writer *w, uint32_t serial, uint32_t seq, uint64_t gran, int bos, int eos,
                     const uint8_t *payload, uint32_t n) {
  uint8_t hdr[27 + 255];
  uint32_t nseg = (n + 254) / 255;
  if (nseg == 0) nseg = 1;
  if (nseg > 255) {
    // split: emit 255*255 then remainder
    uint32_t off = 0;
    uint32_t s = seq;
    while (n - off > 255 * 255) {
      if (emit_page(w, serial, s++, gran, bos && off == 0, 0, payload + off, 255 * 255) < 0)
        return -1;
      off += 255 * 255;
      bos = 0;
    }
    return emit_page(w, serial, s, gran, bos, eos, payload + off, n - off);
  }
  memset(hdr, 0, sizeof(hdr));
  hdr[0] = 'O';
  hdr[1] = 'g';
  hdr[2] = 'g';
  hdr[3] = 'S';
  hdr[5] = (uint8_t)((bos ? 2 : 0) | (eos ? 4 : 0));
  put_le64(hdr + 6, gran);
  put_le32(hdr + 14, serial);
  put_le32(hdr + 18, seq);
  hdr[26] = (uint8_t)nseg;
  uint32_t left = n;
  for (uint32_t i = 0; i < nseg; i++) {
    uint32_t s = left > 255 ? 255 : left;
    hdr[27 + i] = (uint8_t)s;
    left -= s;
  }
  uint32_t hsz = 27 + nseg;
  uint32_t crc = 0;
  for (uint32_t i = 0; i < hsz; i++) crc = (crc << 8) ^ gCrcTab[((crc >> 24) & 0xff) ^ hdr[i]];
  for (uint32_t i = 0; i < n; i++) crc = (crc << 8) ^ gCrcTab[((crc >> 24) & 0xff) ^ payload[i]];
  put_le32(hdr + 22, crc);
  if (emit(w, hdr, hsz) < 0) return -1;
  if (n && emit(w, payload, n) < 0) return -1;
  return 0;
}

// Official integer() at each 0x2000 model slot. Matches stream/mpzz/entropy.go.
static int slot_bit(Range *r, uint8_t *slot, uint32_t offset) {
  if (offset < 12 || (offset & 1) || offset >= 0x2000) return -1;
  return getbit(r, (uint16_t *)(slot + offset));
}

static uint32_t slot_integer(Range *r, uint8_t *slot, int length_bits, int sign_bits, int low_bits,
                             int grouped) {
  int b = slot_bit(r, slot, 12 + 2u * slot[0x08]);
  if (b < 0) return 0;
  slot[0x08] = (uint8_t)((2 * slot[0x08] + b) & 3);
  if (b == 0) {
    slot[0x0a] = 0;
    return 0;
  }
  uint32_t sign = 0;
  if (sign_bits != 0) {
    int sb = slot_bit(r, slot, 20 + 2u * slot[0x09]);
    if (sb < 0) return 0;
    sign = (uint32_t)sb;
    uint32_t smask = (1u << sign_bits) - 1;
    slot[0x09] = (uint8_t)((2u * slot[0x09] + (uint32_t)sb) & smask);
  }
  uint32_t base = 0x34 + ((uint32_t)slot[0x0a] << (length_bits + 1));
  uint32_t v = 1;
  for (int i = 0; i < length_bits; i++) {
    int bit = slot_bit(r, slot, base + 2 * v);
    if (bit < 0) return 0;
    v = 2 * v + (uint32_t)bit;
  }
  uint32_t n = v & ((1u << length_bits) - 1);
  slot[0x0a] = (uint8_t)(n + 1);
  base = 0x834;
  if (grouped) base += n << (low_bits + 1);
  v = 1;
  uint32_t ctx = 1;
  uint32_t cap = low_bits > 0 ? (1u << (low_bits - 1)) : 1;
  uint32_t lmask = low_bits > 0 ? (1u << low_bits) - 1 : 0;
  for (uint32_t i = 0; i < n; i++) {
    int bit = slot_bit(r, slot, base + 2 * ctx);
    if (bit < 0) return 0;
    v = 2 * v + (uint32_t)bit;
    if (ctx < cap) ctx = (2 * ctx + (uint32_t)bit) & lmask;
  }
  return (v ^ (0u - sign)) + sign;
}

static uint32_t slot_predict(uint8_t *slot, uint32_t v, int order) {
  if (order >= 2) {
    uint32_t *d = (uint32_t *)(slot + 4);
    *d += v;
    v = *d;
  }
  if (order >= 1) {
    uint32_t *p = (uint32_t *)slot;
    *p += v;
    v = *p;
  }
  return v;
}

static uint8_t *model_at(uint8_t *mem, int i) { return mem + (uint32_t)i * 0x2000; }

struct PageH {
  uint8_t flags;
  uint64_t granule;
  uint32_t serial, sequence;
  int packets[255];
  uint8_t lacing[512];
  int npackets, nlacing, body;
};

// Official 167c0. xor_flags is 2 on a stream's first page, else 0.
static int decode_page(Range *r, uint8_t *mem, uint16_t *terminal, uint8_t xor_flags,
                       uint32_t gran_base, PageH *h) {
  memset(h, 0, sizeof(*h));
  if (r->err) return -1;
  uint32_t raw = slot_integer(r, model_at(mem, 0), 3, 0, 2, 0);
  if (r->err) return -1;
  h->flags = (uint8_t)(raw ^ xor_flags);
  uint32_t lo = slot_predict(model_at(mem, 1), slot_integer(r, model_at(mem, 1), 5, 2, 4, 0), 1) +
                gran_base;
  uint32_t hi = slot_predict(model_at(mem, 2), slot_integer(r, model_at(mem, 2), 5, 1, 1, 0), 1);
  if (r->err) return -1;
  h->granule = ((uint64_t)hi << 32) | lo;
  h->serial = slot_predict(model_at(mem, 3), slot_integer(r, model_at(mem, 3), 5, 2, 4, 0), 1);
  h->sequence = slot_predict(model_at(mem, 4), slot_integer(r, model_at(mem, 4), 5, 2, 4, 0), 2);
  if (r->err) return -1;
  uint32_t n = slot_integer(r, model_at(mem, 5), 3, 0, 4, 1);
  if (r->err || n > 255) return -1;
  h->npackets = (int)n;
  for (uint32_t i = 0; i < n; i++) {
    uint32_t size = slot_integer(r, model_at(mem, 6), 4, 0, 6, 1);
    if (r->err || size > (16u << 20)) return -1;
    h->packets[i] = (int)size;
    h->body += (int)size;
    while (size >= 255) {
      if (h->nlacing >= 512) return -1;
      h->lacing[h->nlacing++] = 255;
      size -= 255;
    }
    int term = 0;
    if (size == 0 && i + 1 >= n && terminal) term = getbit(r, terminal);
    if (size != 0 || i + 1 < n || term) {
      if (h->nlacing >= 512) return -1;
      h->lacing[h->nlacing++] = (uint8_t)size;
    }
  }
  return 0;
}

static int emit_one_page(Writer *w, uint32_t serial, uint32_t seq, uint64_t gran, int bos, int eos,
                         int cont, const uint8_t *payload, uint32_t pay, const uint8_t *segs,
                         uint32_t nseg);
static int emit_page_pkts(Writer *w, uint32_t serial, uint32_t seq, uint64_t gran, int bos, int eos,
                          const uint8_t *payload, const int *pkts, int np);

static int emit_pageh(Writer *w, const PageH *h, const uint8_t *body) {
  if (h->nlacing <= 255)
    return emit_one_page(w, h->serial, h->sequence, h->granule, (h->flags & 2) != 0,
                         (h->flags & 4) != 0, (h->flags & 1) != 0, body, (uint32_t)h->body, h->lacing,
                         (uint32_t)h->nlacing);
  return emit_page_pkts(w, h->serial, h->sequence, h->granule, (h->flags & 2) != 0,
                        (h->flags & 4) != 0, body, h->packets, h->npackets);
}

static int rewrite_serial(uint8_t *pages, uint32_t n, uint32_t serial) {
  uint32_t pos = 0;
  while (pos + 27 <= n) {
    if (pages[pos] != 'O' || pages[pos + 1] != 'g' || pages[pos + 2] != 'g' || pages[pos + 3] != 'S')
      return -1;
    uint32_t nseg = pages[pos + 26];
    uint32_t hsz = 27 + nseg;
    if (pos + hsz > n) return -1;
    uint32_t body = 0;
    for (uint32_t i = 0; i < nseg; i++) body += pages[pos + 27 + i];
    uint32_t tot = hsz + body;
    if (pos + tot > n) return -1;
    put_le32(pages + pos + 14, serial);
    memset(pages + pos + 22, 0, 4);
    uint32_t crc = 0;
    for (uint32_t i = 0; i < tot; i++)
      crc = (crc << 8) ^ gCrcTab[((crc >> 24) & 0xff) ^ pages[pos + i]];
    put_le32(pages + pos + 22, crc);
    pos += tot;
  }
  return 0;
}

struct HdrEnt {
  uint8_t *pages;
  uint32_t n;
  AudioSt ast;
};

struct DecCtx {
  Range *cmd;
  uint16_t *ctrl;
  uint16_t *lace_term;
  HdrEnt headers[32];
  int nheaders;
  HdrEnt last_cached;
  const uint8_t *last_stream;
  uint32_t last_n;
};

static void ast_clear_books(AudioSt *st) {
  if (!st) return;
  books_free(&st->books);
}

static int ast_clone_setup(AudioSt *dst, const AudioSt *src) {
  if (!dst || !src) return -1;
  ast_clear_books(dst);
  memcpy(dst, src, sizeof(*dst));
  dst->books.tab = 0;
  dst->books.n = 0;
  dst->mem = 0;
  dst->memsz = 0;
  dst->ctx14 = 0;
  memset(dst->res_ctx, 0, sizeof(dst->res_ctx));
  dst->mode = 0;
  dst->first_done = 0;
  if (!src->books.tab || src->books.n <= 0) return 0;
  dst->books.tab = (BookEnt *)calloc((size_t)src->books.n, sizeof(BookEnt));
  if (!dst->books.tab) return -1;
  dst->books.n = src->books.n;
  for (int i = 0; i < src->books.n; i++) {
    dst->books.tab[i].entries = src->books.tab[i].entries;
    dst->books.tab[i].dim = src->books.tab[i].dim;
    dst->books.tab[i].nbits = src->books.tab[i].nbits;
    int e = src->books.tab[i].entries;
    if (src->books.tab[i].len && e > 0) {
      dst->books.tab[i].len = (uint8_t *)malloc((size_t)e);
      if (dst->books.tab[i].len) memcpy(dst->books.tab[i].len, src->books.tab[i].len, (size_t)e);
    }
    if (src->books.tab[i].code && e > 0) {
      dst->books.tab[i].code = (uint32_t *)malloc((size_t)e * sizeof(uint32_t));
      if (dst->books.tab[i].code)
        memcpy(dst->books.tab[i].code, src->books.tab[i].code, (size_t)e * sizeof(uint32_t));
    }
  }
  return 0;
}

// 167c0 header fields (ht/g/ser/seq) via first-bit only (0xffff → 0).
static int decode_hdr_fields(Range *r, uint8_t *mem, int xor_ht, int *ht, int *g0, int *g1,
                             int *ser, int *seqn, int *nse, int *body, int first,
                             int *pkts) {
  // ht: 3-bit unsigned tree at slot 0
  int v = dec_npackets(r, mem + 0x0000);
  if (v < 0) return -1;
  *ht = v ^ xor_ht;
  *g0 = dec_npackets(r, mem + 0x2000);
  *g1 = dec_npackets(r, mem + 0x4000);
  *ser = dec_npackets(r, mem + 0x6000);
  *seqn = dec_npackets(r, mem + 0x8000);
  if (*g0 < 0 || *g1 < 0 || *ser < 0 || *seqn < 0) return -1;
  int np = dec_npackets(r, mem + 0xa000);
  if (np < 0) return -1;
  if (np > 255) np = 255;
  *nse = np;
  *body = 0;
  if (first && np == 1) {
    // Early-return BOS: PE checks lace 0x1e; do not adapt slot 6.
    *body = 0x1e;
    if (pkts) pkts[0] = 0x1e;
    return 0;
  }
  for (int i = 0; i < np; i++) {
    int sl = dec_packet_size(r, mem + 0xc000);
    if (sl < 0) return -1;
    if (pkts) pkts[i] = sl;
    *body += sl;
  }
  return 0;
}

// crc_fill=0: leave 167c0 CRC placeholder (165b0/03690 ht-fail skips page_set_crc).
static int emit_one_page_x(Writer *w, uint32_t serial, uint32_t seq, uint64_t gran, int bos, int eos,
                           int cont, int crc_fill, const uint8_t *payload, uint32_t pay,
                           const uint8_t *segs, uint32_t nseg) {
  uint8_t hdr[27 + 255];
  memset(hdr, 0, sizeof(hdr));
  hdr[0] = 'O';
  hdr[1] = 'g';
  hdr[2] = 'g';
  hdr[3] = 'S';
  hdr[5] = (uint8_t)((cont ? 1 : 0) | (bos ? 2 : 0) | (eos ? 4 : 0));
  put_le64(hdr + 6, gran);
  put_le32(hdr + 14, serial);
  put_le32(hdr + 18, seq);
  hdr[26] = (uint8_t)nseg;
  if (nseg && segs) memcpy(hdr + 27, segs, nseg);
  uint32_t hsz = 27 + nseg;
  if (crc_fill) {
    uint32_t crc = 0;
    for (uint32_t i = 0; i < hsz; i++) crc = (crc << 8) ^ gCrcTab[((crc >> 24) & 0xff) ^ hdr[i]];
    for (uint32_t i = 0; i < pay; i++) crc = (crc << 8) ^ gCrcTab[((crc >> 24) & 0xff) ^ payload[i]];
    put_le32(hdr + 22, crc);
  }
  if (emit(w, hdr, hsz) < 0) return -1;
  if (pay && emit(w, payload, pay) < 0) return -1;
  return 0;
}

static int emit_one_page(Writer *w, uint32_t serial, uint32_t seq, uint64_t gran, int bos, int eos,
                         int cont, const uint8_t *payload, uint32_t pay, const uint8_t *segs,
                         uint32_t nseg) {
  return emit_one_page_x(w, serial, seq, gran, bos, eos, cont, 1, payload, pay, segs, nseg);
}

// 167c0: n_packets, each packet split 0xff laces + rem. Flush page at 255 laces.
static int emit_page_pkts(Writer *w, uint32_t serial, uint32_t seq, uint64_t gran, int bos, int eos,
                          const uint8_t *payload, const int *pkts, int np) {
  uint8_t segs[255];
  uint32_t nseg = 0, pay = 0, poff = 0;
  for (int i = 0; i < np; i++) {
    int sl = pkts[i];
    if (sl < 0) sl = 0;
    int need = sl == 0 ? 1 : (sl + 254) / 255;
    if (sl > 0 && sl % 255 == 0) need++;
    if (nseg && nseg + (uint32_t)need > 255) {
      if (emit_one_page(w, serial, seq++, gran, bos, 0, 0, payload + poff, pay, segs, nseg) < 0)
        return -1;
      poff += pay;
      nseg = 0;
      pay = 0;
      bos = 0;
    }
    if (sl == 0) {
      segs[nseg++] = 0;
      continue;
    }
    int left = sl;
    while (left > 0) {
      if (nseg == 255) {
        if (emit_one_page(w, serial, seq++, gran, bos, 0, 0, payload + poff, pay, segs, nseg) < 0)
          return -1;
        poff += pay;
        nseg = 0;
        pay = 0;
        bos = 0;
      }
      int chunk = left > 255 ? 255 : left;
      segs[nseg++] = (uint8_t)chunk;
      left -= chunk;
      pay += (uint32_t)chunk;
    }
    if (sl % 255 == 0 && nseg < 255) segs[nseg++] = 0;
  }
  if (nseg == 0) {
    segs[0] = 0;
    nseg = 1;
  }
  return emit_one_page(w, serial, seq, gran, bos, eos, 0, payload + poff, pay, segs, nseg);
}

// Extra stream this+0x6c0 / extra_need 0x10008f80 / 0x100123cb.
struct Extra {
  const uint8_t *ptr, *end;
  uint32_t bits;
  int nbits;
  int rem_seg;
  int no_grow;
};

// 03690: next lace. Extra-copy lace bytes into dest (stat!=0 book/frame copy).
static int grow_lace(Writer *w, Extra *ex, const uint8_t *laces, int *idx, int nsegs) {
  if (*idx < 0 || *idx >= nsegs) return 0;
  int lace = laces[*idx];
  (*idx)++;
  if (*idx >= nsegs) *idx = -1;
  ex->rem_seg = lace;
  if (lace > 0 && ex->ptr && ex->ptr < ex->end) {
    uint32_t n = (uint32_t)lace;
    uint32_t have = (uint32_t)(ex->end - ex->ptr);
    if (n > have) n = have;
    if (emit(w, ex->ptr, n) < 0) return 0;
    ex->ptr += n;
    if (n < (uint32_t)lace) {
      uint8_t z = 0;
      for (uint32_t i = n; i < (uint32_t)lace; i++)
        if (emit(w, &z, 1) < 0) return 0;
    }
  }
  return lace;
}

// extra_need: pull `need` bits from extra, grow dest via 03690 when rem_seg==0.
static uint32_t extra_need(Writer *w, Extra *ex, int need, const uint8_t *laces, int *idx,
                          int nsegs) {
  if (ex->nbits < 0) return 0;
  if (ex->nbits >= need) {
    uint32_t v = ex->bits & ((1u << need) - 1);
    ex->bits >>= need;
    ex->nbits -= need;
    return v;
  }
  if (need > 24) {
    uint32_t lo = extra_need(w, ex, 24, laces, idx, nsegs);
    uint32_t hi = extra_need(w, ex, need - 24, laces, idx, nsegs);
    return (hi << 24) + lo;
  }
  if (ex->nbits == 0) ex->bits = 0;
  for (;;) {
    if (ex->rem_seg == 0) {
      if (ex->no_grow || grow_lace(w, ex, laces, idx, nsegs) == 0) {
        ex->nbits = -1;
        return 0;
      }
    }
    ex->rem_seg--;
    if (ex->ptr >= ex->end) {
      ex->nbits = -1;
      return 0;
    }
    uint32_t b = *ex->ptr++;
    uint32_t acc = (b << ex->nbits) + ex->bits;
    int have = ex->nbits + 8;
    if (have < need) {
      ex->nbits = have;
      ex->bits = acc;
      continue;
    }
    ex->nbits = have - need;
    ex->bits = acc >> need;
    return acc & ((1u << need) - 1);
  }
}

// 053cf extra: hunt VCB 0x42,0x43,0x56 in extra (flags books-stat=1).
static int extra_hunt_vcb(Writer *w, Extra *ex, const uint8_t *laces, int *idx, int nsegs) {
  for (;;) {
    uint32_t b = extra_need(w, ex, 8, laces, idx, nsegs);
    if (ex->nbits < 0) return -1;
    if (b != 0x42) continue;
    b = extra_need(w, ex, 8, laces, idx, nsegs);
    if (ex->nbits < 0) return -1;
    if (b != 0x43) continue;
    b = extra_need(w, ex, 8, laces, idx, nsegs);
    if (ex->nbits < 0) return -1;
    if (b == 0x56) return 0;
  }
}

// 03690 extra: hunt 'OggS' then copy remaining extra page bytes.
static int extra_hunt_oggs(Writer *w, Extra *ex) {
  if (!ex->ptr || ex->ptr >= ex->end) return -1;
  const uint8_t *p = ex->ptr;
  const uint8_t *e = ex->end;
  while (p + 4 <= e) {
    if (p[0] == 'O' && p[1] == 'g' && p[2] == 'g' && p[3] == 'S') {
      ex->ptr = p;
      return 0;
    }
    p++;
  }
  return -1;
}

#ifdef HOST_DEBUG
static uint64_t gCopyTrunc, gCopyWant, gCopyGot, gCopyFail, gCopyOk;
#endif

// Copy one extra Ogg page (header+nseg laces+body). Never drop CRC/laces/tail.
static int extra_copy_page(Writer *w, Extra *ex) {
  if (extra_hunt_oggs(w, ex) < 0) {
#ifdef HOST_DEBUG
    gCopyFail++;
#endif
    return -1;
  }
  const uint8_t *p = ex->ptr;
  if (p + 27 > ex->end) {
#ifdef HOST_DEBUG
    gCopyFail++;
#endif
    return -1;
  }
  uint32_t nseg = p[26];
  uint32_t hsz = 27 + nseg;
  if (p + hsz > ex->end) {
#ifdef HOST_DEBUG
    gCopyFail++;
#endif
    return -1;
  }
  uint32_t body = 0;
  for (uint32_t i = 0; i < nseg; i++) body += p[27 + i];
  uint32_t tot = hsz + body;
#ifdef HOST_DEBUG
  gCopyWant += tot;
#endif
  if (p + tot > ex->end) {
#ifdef HOST_DEBUG
    gCopyTrunc += (uint64_t)tot - (uint64_t)(ex->end - p);
#endif
    // Incomplete page at extra_end: wrap to dest start and copy a full page.
    const uint8_t *save = ex->ptr;
    ex->ptr = w->dst;
    if (ex->ptr == save || extra_hunt_oggs(w, ex) < 0) {
      ex->ptr = save;
#ifdef HOST_DEBUG
      gCopyFail++;
#endif
      return -1;
    }
    p = ex->ptr;
    if (p + 27 > ex->end) return -1;
    nseg = p[26];
    hsz = 27 + nseg;
    if (p + hsz > ex->end) return -1;
    body = 0;
    for (uint32_t i = 0; i < nseg; i++) body += p[27 + i];
    tot = hsz + body;
    if (p + tot > ex->end) {
#ifdef HOST_DEBUG
      gCopyFail++;
#endif
      return -1;
    }
  }
  if (emit(w, p, tot) < 0) return -1;
  ex->ptr += tot;
#ifdef HOST_DEBUG
  gCopyGot += tot;
  gCopyOk++;
#endif
  return (int)tot;
}

// Copy extra ident+comment+setup (packet types 1/3/5) for a subsequent solid file.
static int extra_copy_headers(Writer *w, Extra *ex) {
  int n = 0, got = 0;
  Extra save = *ex;
  while (n < 8) {
    const uint8_t *p = ex->ptr;
    if (extra_hunt_oggs(w, ex) < 0) break;
    if (ex->ptr + 28 > ex->end) break;
    uint32_t nseg = ex->ptr[26];
    uint32_t hsz = 27 + nseg;
    if (ex->ptr + hsz > ex->end) break;
    uint8_t ptype = ex->ptr[hsz];
    if (n > 0 && ptype != 1 && ptype != 3 && ptype != 5) {
      *ex = save;
      break;
    }
    int c = extra_copy_page(w, ex);
    if (c <= 0) break;
    got += c;
    save = *ex;
    n++;
    (void)p;
  }
  return got;
}

// 0x1000a790 stat==0: 8-bit dest byte (comment payload).
static int dec_a790_byte(Range *r, uint8_t *slot) {
  int ctx = slot[0x08];
  int bit = getbit(r, (uint16_t *)(slot + 0x0c + 2 * ctx));
  if (bit < 0) return -1;
  slot[0x08] = (uint8_t)((bit + 2 * ctx) & 3);
  int v = 2 * bit + 4;
  for (int i = 0; i < 7; i++) {
    bit = getbit(r, (uint16_t *)(slot + 0x0c + 2 * (v & 3)));
    if (bit < 0) return -1;
    if (i == 0)
      v = v + bit;
    else
      v = 2 * v + bit;
  }
  return v & 255;
}

// 02790 writes mode+residue; leftover lace bytes stay 0.

// 15e80 unsigned 5-bit tree + extra_walk (comment length). slot+0x6a000.
static int dec_u5(Range *rc, uint8_t *slot) {
  int ctx = slot[0x08];
  int bit = getbit(rc, (uint16_t *)(slot + 0x0c + 2 * ctx));
  if (bit < 0) return -1;
  slot[0x08] = (uint8_t)((bit + 2 * ctx) & 3);
  if (bit == 0) {
    slot[0x0a] = 0;
    return 0;
  }
  uint8_t *node = slot + 0x34 + ((int)slot[0x0a] << 6);
  bit = getbit(rc, (uint16_t *)(node + 2));
  if (bit < 0) return -1;
  int v = 4 + 2 * bit;
  bit = getbit(rc, (uint16_t *)(node + v));
  if (bit < 0) return -1;
  v = v + bit;
  for (int i = 0; i < 3; i++) {
    bit = getbit(rc, (uint16_t *)(node + 2 * v));
    if (bit < 0) return -1;
    v = bit + 2 * v;
  }
  int n = v & 31;
  slot[0x0a] = (uint8_t)(n + 1);
  int extra = 1;
  if (n > 0) {
    uint8_t *base = slot + 0x834 + (n << 3);
    bit = getbit(rc, (uint16_t *)(base + 2));
    if (bit < 0) return -1;
    extra = bit + 2;
    int si = (2 + bit) & 3;
    for (int i = 1; i < n; i++) {
      bit = getbit(rc, (uint16_t *)(base + 2 * si));
      if (bit < 0) return -1;
      extra = bit + 2 * extra;
      if (si < 2) si = (2 * si + bit) & 3;
    }
  }
  return extra;
}

// 123b0: stat==0 range-decode+write; stat!=0 extra_need nbits.
static int fn_123b0(int stat, Range *rc, Writer *w, Extra *ex, const uint8_t *laces, int *idx,
                    int nsegs, int nbits, uint8_t *slot, int extra_sel) {
  if (stat != 0) return (int)extra_need(w, ex, nbits, laces, idx, nsegs);
  return range_dec_signed_3(rc, slot, extra_sel);
}

// 123b0 stat==0 value: signed_3 + pred. nbits is dest-only (053cf wr8).
static int dec_123b0_val(Range *rc, uint8_t *slot, int extra_sel, int pred) {
  int val = range_dec_signed_3(rc, slot, extra_sel);
  if (val == (int)0x80000000) val = 0;
  if (pred != 0) {
    if (pred > 1) {
      val += *(int32_t *)(slot + 4);
      *(int32_t *)(slot + 4) = val;
    }
    val += *(int32_t *)slot;
    *(int32_t *)slot = val;
  }
  return val;
}

// Fork PE 053cf residue type(149e0)+begin/end/psize(123b0 24). Dest wr8 stays signed_3.
static void pe_res_hdr(Range *r, uint8_t *mem, int *begin, int *end, int *psize) {
  Range rsave = *r;
  uint8_t *win_save = 0;
  if (r->win && r->win_cap) {
    win_save = (uint8_t *)malloc(r->win_cap);
    if (win_save) memcpy(win_save, r->win, r->win_cap);
  }
  uint8_t sl0[0x2000], sl1[0x2000], sl2[0x2000], stype[0x40];
  memcpy(sl0, mem + 0x40000, 0x2000);
  memcpy(sl1, mem + 0x42000, 0x2000);
  memcpy(sl2, mem + 0x44000, 0x2000);
  memcpy(stype, mem + 0x2248, 0x40);
  // 149e0 residue type: 1 getbit at slot 0x2248, write 16 (skipped here).
  {
    uint8_t *slot = mem + 0x2248;
    int ctx = slot[0x08];
    int bit = getbit(r, (uint16_t *)(slot + 0x0c + 2 * ctx));
    if (bit >= 0) slot[0x08] = (uint8_t)((bit + 2 * ctx) & 3);
  }
  int b = dec_123b0_val(r, mem + 0x40000, 0, 1);
  int e = dec_123b0_val(r, mem + 0x42000, 0, 1);
  int p = dec_123b0_val(r, mem + 0x44000, 1, 1) + 1;
  if (p < 1) p = 1;
  memcpy(mem + 0x40000, sl0, 0x2000);
  memcpy(mem + 0x42000, sl1, 0x2000);
  memcpy(mem + 0x44000, sl2, 0x2000);
  memcpy(mem + 0x2248, stype, 0x40);
  uint8_t *keep = r->win;
  *r = rsave;
  r->win = keep;
  if (win_save && keep && rsave.win_cap) memcpy(keep, win_save, rsave.win_cap);
  free(win_save);
  *begin = b;
  *end = e;
  *psize = p;
}

// 053cf/057aa: \x05vorbis + nbooks via 123b0, then per-book VCB/dim/ent/lengths.
// First ident is stat==0 (1bb0 clears +0x69). Subsequent files copy dest pages.
static int decode_setup(Range *r, uint8_t *mem, uint8_t *out, int cap, int *nbooks_out, int stat,
                        Writer *w, Extra *ex, AudioSt *ast) {
  int pos = 0, bitpos = 0;
  if (cap > 0) out[0] = 0;
  auto wr8 = [&](uint32_t v, int nb) {
    for (int i = 0; i < nb && pos < cap; i++) {
      out[pos] |= (uint8_t)(((v >> i) & 1) << bitpos);
      bitpos++;
      if (bitpos == 8) {
        bitpos = 0;
        pos++;
        if (pos < cap) out[pos] = 0;
      }
    }
  };
  auto wr_flush = [&]() {
    if (bitpos && pos < cap) pos++;
    bitpos = 0;
  };
  auto dec1 = [&](uint8_t *slot) -> int {
    int ctx = slot[0x08];
    int bit = getbit(r, (uint16_t *)(slot + 0x0c + 2 * ctx));
    if (bit < 0) return 0;
    slot[0x08] = (uint8_t)((bit + 2 * ctx) & 3);
    wr8((uint32_t)bit, 1);
    return bit;
  };
  uint8_t dummy_lace = 255;
  int dummy_idx = 0;
  wr8(0x05, 8);
  for (int i = 0; i < 6; i++) wr8((uint8_t)"vorbis"[i], 8);
  int nb;
  if (stat != 0 && ex && ex->ptr) {
    extra_hunt_vcb(w, ex, &dummy_lace, &dummy_idx, 1);
    nb = fn_123b0(stat, r, w, ex, &dummy_lace, &dummy_idx, 1, 8, mem + 0x20000, 1);
  } else {
    nb = range_dec_signed_3(r, mem + 0x20000, 1);
  }
  if (nb == (int)0x80000000) nb = 0;
  nb += 1;
  if (nb < 1) nb = 1;
  if (nb > 256) nb = 256;
  *nbooks_out = nb;
  wr8((uint32_t)(nb - 1), 8);
  int dim = 0, ent = 0, floors = 0, res = 0, maps = 0, modes = 0;
  if (ast) {
    books_free(&ast->books);
    ast->books.tab = (BookEnt *)calloc((size_t)nb, sizeof(BookEnt));
    ast->books.n = ast->books.tab ? nb : 0;
    for (int c = 0; c < 16; c++) {
      ast->classbook[c] = 0;
      ast->dimc[c] = 1;
      ast->bitsc[c] = 0;
      for (int j = 0; j < 8; j++) {
        ast->cascade[c][j] = -1;
        ast->class_vals[c][j] = -1;
      }
    }
    ast->npart = 0;
    ast->floor_nvals = 0;
    ast->floor_mult = 0;
    ast->res_ok = 0;
    ast->res_type = 0;
    ast->res_ncl = 0;
    ast->res_classbook = 0;
    ast->res_begin = 0;
    ast->res_end = 0;
    ast->res_psize = 0;
    memset(ast->res_cascade, 0, sizeof(ast->res_cascade));
    for (int c = 0; c < 16; c++)
      for (int j = 0; j < 8; j++) ast->res_books[c][j] = -1;
    memset(ast->xlist, 0, sizeof(ast->xlist));
    if (nb > 0) {
      ast->xlist[1] = 1;
    }
  }
  for (int i = 0; i < nb && pos + 16 < cap; i++) {
    wr8(0x564342, 24);
    int d, e;
    if (stat != 0 && ex && ex->ptr && extra_hunt_vcb(w, ex, &dummy_lace, &dummy_idx, 1) == 0) {
      d = fn_123b0(stat, r, w, ex, &dummy_lace, &dummy_idx, 1, 16, mem + 0x22000, 0);
      e = fn_123b0(stat, r, w, ex, &dummy_lace, &dummy_idx, 1, 24, mem + 0x24000, 0);
    } else {
      d = range_dec_signed_4(r, mem + 0x22000);
      e = range_dec_u5_wide(r, mem + 0x24000);
    }
    if (d == (int)0x80000000) d = 0;
    if (e < 0) e = 0;
    if (d < 0) d = -d;
    if (e < 0) e = -e;
    if (d > 16) d = 16;
    if (e > 65536) e = 65536;
    if (i == 0) {
      dim = d;
      ent = e;
    }
    wr8((uint32_t)d, 16);
    wr8((uint32_t)e, 24);
    uint8_t *lens = 0;
    if (ast && ast->books.tab && i < ast->books.n && e > 0) {
      lens = (uint8_t *)calloc((size_t)e, 1);
      ast->books.tab[i].entries = e;
      ast->books.tab[i].dim = d;
      ast->books.tab[i].len = lens;
    }
    int ordered = dec1(mem + 0x2218);
    if (ordered) {
      // Dest wr8 stays signed_3 extra_sel=1 (size lock). Books store 0 for unused.
      int clen = range_dec_signed_3(r, mem + 0x26000, 1);
      if (clen == (int)0x80000000) clen = 0;
      clen += 1;
      int wr_clen = clen;
      if (wr_clen < 1) wr_clen = 1;
      if (wr_clen > 32) wr_clen = 32;
      wr8((uint32_t)(wr_clen - 1), 5);
      int filled = 0;
      while (filled < e && pos < cap) {
        int nbits = vorbis_ilog((uint32_t)(e - filled));
        if (nbits < 1) nbits = 1;
        int num = range_dec_signed_3(r, mem + 0x28000, 0);
        if (num == (int)0x80000000) num = 0;
        if (num < 0) num = -num;
        uint32_t mask = nbits >= 32 ? 0xffffffffu : ((1u << nbits) - 1);
        wr8((uint32_t)num & mask, nbits);
        if (num < 1) num = 1;
        if (filled + num > e) num = e - filled;
        if (lens) {
          uint8_t L = (clen >= 1 && clen <= 32) ? (uint8_t)clen : 0;
          for (int t = 0; t < num; t++) lens[filled + t] = L;
        }
        filled += num;
        clen++;
      }
    } else {
      int sparse = dec1(mem + 0x221a);
      for (int k = 0; k < e && pos < cap; k++) {
        int used = 1;
        if (sparse) used = dec1(mem + 0x221c);
        if (!used) continue;
        int ln = range_dec_signed_3(r, mem + 0x2a000, 1);
        if (ln == (int)0x80000000) ln = 0;
        ln += 1;
        int wr_ln = ln;
        if (wr_ln < 1) wr_ln = 1;
        if (wr_ln > 32) wr_ln = 32;
        wr8((uint32_t)(wr_ln - 1), 5);
        // Vorbis used lengths are 1..32. Invalid/unused is 0, not 32-for-unused.
        if (lens) lens[k] = (ln >= 1 && ln <= 32) ? (uint8_t)ln : 0;
      }
    }
    if (ast && ast->books.tab && i < ast->books.n) book_build(&ast->books.tab[i]);
    int lookup = range_dec_signed_3(r, mem + 0x2c000, 0);
    if (lookup == (int)0x80000000) lookup = 0;
    if (lookup < 0) lookup = -lookup;
    lookup &= 15;
    wr8((uint32_t)lookup, 4);
    if (lookup > 0 && lookup <= 2 && d > 0) {
      int mn = range_dec_signed_3(r, mem + 0x2c000, 0);
      int del = range_dec_signed_3(r, mem + 0x2c000, 0);
      if (mn == (int)0x80000000) mn = 0;
      if (del == (int)0x80000000) del = 0;
      wr8((uint32_t)mn, 32);
      wr8((uint32_t)del, 32);
      int vbits = range_dec_signed_3(r, mem + 0x2c000, 1);
      if (vbits == (int)0x80000000) vbits = 0;
      vbits += 1;
      if (vbits < 1) vbits = 1;
      if (vbits > 32) vbits = 32;
      wr8((uint32_t)(vbits - 1), 4);
      dec1(mem + 0x2224);
      uint32_t vals;
      if (lookup == 1) {
        vals = 1;
        for (int p = 0; p < d && vals < 0x1000000u; p++) {
          uint32_t acc = 1, n = 0;
          while (acc < (uint32_t)e) {
            acc *= (vals + 1);
            n++;
            if (n > 32) break;
          }
          vals = n ? n : 1;
        }
        if (vals > 65536) vals = 65536;
      } else {
        vals = (uint32_t)d * (uint32_t)e;
        if (vals > 65536) vals = 65536;
      }
      for (uint32_t t = 0; t < vals && pos < cap; t++) {
        int m = range_dec_signed_3(r, mem + 0x2e000, 0);
        if (m == (int)0x80000000) m = 0;
        if (m < 0) m = -m;
        wr8((uint32_t)m, vbits);
      }
    }
  }
  int book_end = pos;
  int nt = range_dec_signed_3(r, mem + 0x30000, 1);
  if (nt == (int)0x80000000) nt = 0;
  nt += 1;
  if (nt < 1) nt = 1;
  if (nt > 64) nt = 64;
  wr8((uint32_t)(nt - 1), 6);
  for (int i = 0; i < nt && pos + 2 < cap; i++) wr8(0, 16);
  int nf = range_dec_signed_3(r, mem + 0x32000, 1);
  if (nf == (int)0x80000000) nf = 0;
  nf += 1;
  if (nf < 1) nf = 1;
  if (nf > 64) nf = 64;
  floors = nf;
  wr8((uint32_t)(nf - 1), 6);
  FloorRec flrec[64];
  memset(flrec, 0, sizeof(flrec));
  ResidueRec rrec[64];
  memset(rrec, 0, sizeof(rrec));
  int last_type1 = -1;
  int map0_fl = -1;
  int map0_rs = -1;
  int dest_begin = 0, dest_end = 0, dest_psize = 0;
  // 062d7 floor1: type(16 via 149e0) + partitions(5) + classes + X_list.
  for (int i = 0; i < nf && pos + 16 < cap; i++) {
    int ftype = dec1(mem + 0x2226);
    if (ftype < 0) ftype = 0;
    wr8((uint32_t)(ftype ? 1 : 0), 16);
    if (!ftype) continue;
    int parts = range_dec_signed_3(r, mem + 0x34000, 0);
    if (parts == (int)0x80000000) parts = 0;
    if (parts < 0) parts = -parts;
    if (parts > 31) parts = 31;
    wr8((uint32_t)parts, 5);
    int cls[32] = {};
    int maxc = 0;
    for (int p = 0; p < parts && pos < cap; p++) {
      int c = range_dec_signed_3(r, mem + 0x36000, 0);
      if (c == (int)0x80000000) c = 0;
      if (c < 0) c = -c;
      c &= 15;
      cls[p] = c;
      if (c > maxc) maxc = c;
      wr8((uint32_t)c, 4);
    }
    int cdim[16] = {}, csub[16] = {}, fcb[16] = {};
    int16_t sbooks[16][8];
    for (int c = 0; c < 16; c++)
      for (int j = 0; j < 8; j++) sbooks[c][j] = -1;
    for (int c = 0; c <= maxc && c < 16 && pos < cap; c++) {
      int dimc = range_dec_signed_3(r, mem + 0x2228, 0);
      if (dimc == (int)0x80000000) dimc = 0;
      if (dimc < 0) dimc = -dimc;
      dimc &= 7;
      cdim[c] = dimc + 1;
      wr8((uint32_t)dimc, 3);
      int sub = dec1(mem + 0x2230);
      if (sub < 0) sub = 0;
      sub &= 3;
      // 11bb0 is a 2-bit decode; two getbits if dec1 only gave LSB.
      int sub2 = dec1(mem + 0x2230);
      if (sub2 > 0) sub |= 2;
      sub &= 3;
      csub[c] = sub;
      wr8((uint32_t)sub, 2);
      if (sub) {
        int cb = range_dec_signed_3(r, mem + 0x38000, 0);
        if (cb == (int)0x80000000) cb = 0;
        if (cb < 0) cb = -cb;
        wr8((uint32_t)cb & 255, 8);
        fcb[c] = cb & 255;
      }
      int nsub = 1 << sub;
      for (int j = 0; j < nsub && pos < cap; j++) {
        int sb = range_dec_signed_3(r, mem + 0x3a000, 0);
        if (sb == (int)0x80000000) sb = 0;
        if (sb < 0) sb = -sb;
        wr8((uint32_t)(sb + 1) & 255, 8);
        if (j < 8) sbooks[c][j] = (int16_t)sb;
      }
    }
    int mult = dec1(mem + 0x2234);
    int mult2 = dec1(mem + 0x2234);
    if (mult < 0) mult = 0;
    if (mult2 > 0) mult |= 2;
    mult &= 3;
    wr8((uint32_t)mult, 2);
    int rbits = range_dec_signed_3(r, mem + 0x2238, 0);
    if (rbits == (int)0x80000000) rbits = 0;
    if (rbits < 0) rbits = -rbits;
    rbits &= 15;
    wr8((uint32_t)rbits, 4);
    int nvals = 2;
    for (int p = 0; p < parts; p++) nvals += cdim[cls[p]];
    if (nvals > 65) nvals = 65;
    if (rbits < 1) rbits = 1;
    uint8_t xsave[65];
    memset(xsave, 0, sizeof(xsave));
    xsave[1] = 1;
    for (int x = 2; x < nvals && pos < cap; x++) {
      int xv = range_dec_signed_3(r, mem + 0x3a000, 0);
      if (xv == (int)0x80000000) xv = 0;
      if (xv < 0) xv = -xv;
      wr8((uint32_t)xv & ((1u << rbits) - 1), rbits);
      xsave[x] = (uint8_t)(xv & 0xff);
    }
    if (i >= 0 && i < 64) {
      flrec[i].ok = 1;
      flrec[i].nvals = nvals;
      flrec[i].mult = (uint8_t)mult;
      flrec[i].npart = (uint8_t)parts;
      memcpy(flrec[i].xlist, xsave, 65);
      memset(flrec[i].pclass, 0, sizeof(flrec[i].pclass));
      for (int p = 0; p < parts && p < 31; p++) flrec[i].pclass[p + 1] = (uint8_t)cls[p];
      for (int c = 0; c < 16; c++) {
        flrec[i].dimc[c] = (uint8_t)cdim[c];
        flrec[i].bitsc[c] = (uint8_t)csub[c];
        flrec[i].cbook[c] = (uint8_t)fcb[c];
        for (int j = 0; j < 8; j++) flrec[i].sub[c][j] = sbooks[c][j];
      }
      last_type1 = i;
    }
  }
  int nr = range_dec_signed_3(r, mem + 0x3c000, 1);
  if (nr == (int)0x80000000) nr = 0;
  nr += 1;
  if (nr < 1) nr = 1;
  if (nr > 64) nr = 64;
  res = nr;
  wr8((uint32_t)(nr - 1), 6);
  // Vorbis residue header + cascade (PE 053cf after floors).
  for (int i = 0; i < nr && pos + 16 < cap; i++) {
    int pe_begin = 0, pe_end = 0, pe_psize = 0;
    // Residue 0 AudioSt: PE 149e0 type + 123b0 24-bit begin/end/psize. Dest wr8 unchanged.
    if (i == 0) pe_res_hdr(r, mem, &pe_begin, &pe_end, &pe_psize);
    int rtype = range_dec_signed_3(r, mem + 0x3c000, 0);
    if (rtype == (int)0x80000000) rtype = 0;
    if (rtype < 0) rtype = -rtype;
    rtype &= 3;
    wr8((uint32_t)rtype, 16);
    int begin = range_dec_signed_3(r, mem + 0x3e000, 0);
    int end = range_dec_signed_3(r, mem + 0x3e000, 0);
    int psize = range_dec_signed_3(r, mem + 0x3e000, 0);
    if (begin == (int)0x80000000) begin = 0;
    if (end == (int)0x80000000) end = 0;
    if (psize == (int)0x80000000) psize = 0;
    if (begin < 0) begin = -begin;
    if (end < 0) end = -end;
    if (psize < 0) psize = -psize;
    // Residue 0 dest: PE 123b0 signed 24-bit (begin=-39 → 0xffffd9),
    // not abs(signed_3). Same 24+24+24 width; size stays locked.
    if (i == 0) {
      wr8((uint32_t)pe_begin & 0xffffffu, 24);
      wr8((uint32_t)pe_end & 0xffffffu, 24);
      wr8((uint32_t)pe_psize & 0xffffffu, 24);
      dest_begin = pe_begin;
      dest_end = pe_end;
      dest_psize = pe_psize;
    } else {
      wr8((uint32_t)begin, 24);
      wr8((uint32_t)end, 24);
      wr8((uint32_t)psize, 24);
    }
    int ncl = range_dec_signed_3(r, mem + 0x3c000, 1);
    if (ncl == (int)0x80000000) ncl = 0;
    if (ncl < 0) ncl = -ncl;
    ncl = (ncl & 63) + 1;
    if (ncl > 64) ncl = 64;
    wr8((uint32_t)(ncl - 1), 6);
    int cbook = range_dec_signed_3(r, mem + 0x3c000, 0);
    if (cbook == (int)0x80000000) cbook = 0;
    if (cbook < 0) cbook = -cbook;
    wr8((uint32_t)cbook & 255, 8);
    int casc[64] = {};
    for (int c = 0; c < ncl && pos < cap; c++) {
      int hi = range_dec_signed_3(r, mem + 0x40000, 0);
      if (hi == (int)0x80000000) hi = 0;
      if (hi < 0) hi = -hi;
      hi &= 7;
      wr8((uint32_t)hi, 3);
      int bit = dec1(mem + 0x40008);
      wr8((uint32_t)(bit > 0), 1);
      int lo = 0;
      if (bit > 0) {
        lo = range_dec_signed_3(r, mem + 0x40000, 0);
        if (lo == (int)0x80000000) lo = 0;
        if (lo < 0) lo = -lo;
        lo &= 31;
        wr8((uint32_t)lo, 5);
      }
      casc[c] = hi + (lo << 3);
    }
    int16_t rbooks[16][8];
    for (int c = 0; c < 16; c++)
      for (int j = 0; j < 8; j++) rbooks[c][j] = -1;
    for (int c = 0; c < ncl && pos < cap; c++) {
      for (int j = 0; j < 8 && pos < cap; j++) {
        if (casc[c] & (1 << j)) {
          int b = range_dec_signed_3(r, mem + 0x40000, 0);
          if (b == (int)0x80000000) b = 0;
          if (b < 0) b = -b;
          wr8((uint32_t)b & 255, 8);
          // PE stores 8-bit book indexes. Clamp to 0..nbooks-1; cascade is a bitmask.
          int bid = b & 255;
          if (c < 16) rbooks[c][j] = (bid < nb) ? (int16_t)bid : (int16_t)-1;
        }
      }
    }
    if (i >= 0 && i < 64) {
      rrec[i].ok = 1;
      rrec[i].type = (uint8_t)rtype;
      rrec[i].ncl = (uint8_t)ncl;
      rrec[i].classbook = (uint8_t)(cbook & 255);
      rrec[i].begin = pe_begin;
      rrec[i].end = pe_end;
      rrec[i].psize = pe_psize;
      for (int c = 0; c < 16; c++) {
        rrec[i].cascade[c] = (c < ncl) ? casc[c] : 0;
        for (int j = 0; j < 8; j++) rrec[i].books[c][j] = rbooks[c][j];
      }
    }
  }
  int nm = range_dec_signed_3(r, mem + 0x42000, 1);
  if (nm == (int)0x80000000) nm = 0;
  nm += 1;
  if (nm < 1) nm = 1;
  if (nm > 64) nm = 64;
  maps = nm;
  wr8((uint32_t)(nm - 1), 6);
  // mapping type 0 (PE after residues): submaps, coupling, mux, floor/res.
  for (int i = 0; i < nm && pos + 8 < cap; i++) {
    wr8(0, 16);
    int flag = dec1(mem + 0x42008);
    wr8((uint32_t)(flag > 0), 1);
    int nsub = 1;
    if (flag > 0) {
      int s = range_dec_signed_3(r, mem + 0x42000, 0);
      if (s == (int)0x80000000) s = 0;
      if (s < 0) s = -s;
      s &= 15;
      nsub = s + 1;
      wr8((uint32_t)s, 4);
    }
    int coup = dec1(mem + 0x4200a);
    wr8((uint32_t)(coup > 0), 1);
    int ncoup = 0;
    if (coup > 0) {
      int c = range_dec_signed_3(r, mem + 0x44000, 0);
      if (c == (int)0x80000000) c = 0;
      if (c < 0) c = -c;
      c &= 255;
      ncoup = c + 1;
      wr8((uint32_t)c, 8);
      for (int k = 0; k < ncoup && pos < cap; k++) {
        wr8(0, 8);
        wr8(0, 8);
      }
    }
    if (nsub > 1) {
      for (int chn = 0; chn < 8 && pos < cap; chn++) {
        int mx = range_dec_signed_3(r, mem + 0x42000, 0);
        if (mx == (int)0x80000000) mx = 0;
        if (mx < 0) mx = -mx;
        wr8((uint32_t)mx & 15, 4);
      }
    }
    for (int s = 0; s < nsub && pos < cap; s++) {
      wr8(0, 8);
      int fl = range_dec_signed_3(r, mem + 0x42000, 0);
      int rs = range_dec_signed_3(r, mem + 0x3c000, 0);
      if (fl == (int)0x80000000) fl = 0;
      if (rs == (int)0x80000000) rs = 0;
      if (fl < 0) fl = -fl;
      if (rs < 0) rs = -rs;
      wr8((uint32_t)fl & 255, 8);
      wr8((uint32_t)rs & 255, 8);
      if (i == 0 && s == 0) {
        map0_fl = fl & 255;
        map0_rs = rs & 255;
      }
    }
  }
  int nmo = range_dec_signed_3(r, mem + 0x46000, 1);
  if (nmo == (int)0x80000000) nmo = 0;
  nmo += 1;
  if (nmo < 1) nmo = 1;
  if (nmo > 64) nmo = 64;
  modes = nmo;
  wr8((uint32_t)(nmo - 1), 6);
  for (int i = 0; i < nmo && pos + 2 < cap; i++) {
    wr8(0, 1);
    wr8(0, 16);
    wr8(0, 16);
    wr8(0, 8);
  }
  wr8(1, 1);
  wr_flush();
  if (ast) {
    ast->nmodes = modes > 0 ? modes : 1;
    ast->ready = 1;
    int use = -1;
    if (map0_fl >= 0 && map0_fl < 64) use = map0_fl;
    else if (flrec[0].ok) use = 0;
    else use = last_type1;
    if (use >= 0 && use < 64 && flrec[use].ok) {
      ast->floor_nvals = flrec[use].nvals;
      ast->floor_mult = flrec[use].mult;
      ast->npart = flrec[use].npart;
      memcpy(ast->xlist, flrec[use].xlist, 65);
      memcpy(ast->part_class, flrec[use].pclass, 32);
      memcpy(ast->dimc, flrec[use].dimc, 16);
      memcpy(ast->bitsc, flrec[use].bitsc, 16);
      memcpy(ast->classbook, flrec[use].cbook, 16);
      for (int c = 0; c < 16; c++) {
        for (int j = 0; j < 8; j++) {
          ast->cascade[c][j] = flrec[use].sub[c][j];
          ast->class_vals[c][j] = flrec[use].sub[c][j];
        }
      }
    }
    int ruse = -1;
    if (map0_rs >= 0 && map0_rs < 64 && rrec[map0_rs].ok) ruse = map0_rs;
    else {
      for (int i = 0; i < 64; i++) {
        if (rrec[i].ok) {
          ruse = i;
          break;
        }
      }
    }
    if (ruse >= 0 && ruse < 64 && rrec[ruse].ok) {
      ast->res_ok = 1;
      ast->res_type = rrec[ruse].type;
      ast->res_ncl = rrec[ruse].ncl;
      ast->res_classbook = rrec[ruse].classbook;
      ast->res_begin = rrec[ruse].begin;
      ast->res_end = rrec[ruse].end;
      ast->res_psize = rrec[ruse].psize;
      memcpy(ast->res_cascade, rrec[ruse].cascade, sizeof(ast->res_cascade));
      for (int c = 0; c < 16; c++)
        for (int j = 0; j < 8; j++) ast->res_books[c][j] = rrec[ruse].books[c][j];
    }
#ifdef HOST_DEBUG
    int n_t0 = 0, n_t1 = 0;
    for (int i = 0; i < 64; i++) {
      if (flrec[i].ok) n_t1++;
    }
    n_t0 = floors - n_t1;
    fprintf(stderr, "  ast nmodes=%d floor_n=%d npart=%d books=%d dimc0=%d bitsc0=%d cb0=%d mapfl=%d use=%d last1=%d t0=%d t1=%d\n",
            ast->nmodes, ast->floor_nvals, ast->npart, ast->books.n, ast->dimc[0], ast->bitsc[0],
            ast->classbook[0], map0_fl, use, last_type1, n_t0, n_t1);
    for (int i = 0; i < 64; i++) {
      if (flrec[i].ok)
        fprintf(stderr, "  fl%d npart=%d nvals=%d mult=%d\n", i, flrec[i].npart, flrec[i].nvals,
                flrec[i].mult);
    }
    fprintf(stderr, "  ast res ok=%d type=%d ncl=%d cbook=%d begin=%d end=%d psize=%d casc0=%d maprs=%d ruse=%d\n",
            ast->res_ok, ast->res_type, ast->res_ncl, ast->res_classbook, ast->res_begin, ast->res_end,
            ast->res_psize, ast->res_cascade[0], map0_rs, ruse);
    fprintf(stderr, "  dest res begin=%d end=%d psize=%d (wr8 signed_3)\n", dest_begin, dest_end,
            dest_psize);
    {
      int grouping = ast->res_psize < 1 ? 1 : ast->res_psize;
      int npart = 0;
      if (ast->res_end > ast->res_begin) npart = (ast->res_end - ast->res_begin) / grouping;
      fprintf(stderr, "  ast res npart=(%d-(%d))/%d=%d\n", ast->res_end, ast->res_begin, grouping,
              npart);
      for (int c = 0; c < ast->res_ncl && c < 16; c++) {
        fprintf(stderr, "  res c=%d casc=%d books=", c, ast->res_cascade[c]);
        for (int s = 0; s < 8; s++) fprintf(stderr, "%d%s", ast->res_books[c][s], s < 7 ? "," : "");
        fprintf(stderr, "\n");
      }
      if (ast->books.tab) {
        for (int i = 0; i < ast->books.n && i < 6; i++) {
          BookEnt *b = &ast->books.tab[i];
          int l0 = (b->len && b->entries > 0) ? b->len[0] : -1;
          fprintf(stderr, "  book%d dim=%d ent=%d nbits=%d len0=%d lens=", i, b->dim, b->entries,
                  b->nbits, l0);
          int nshow = b->entries < 8 ? b->entries : 8;
          for (int k = 0; k < nshow; k++) {
            int lk = (b->len && k < b->entries) ? b->len[k] : -1;
            fprintf(stderr, "%d%s", lk, k + 1 < nshow ? "," : "");
          }
          fprintf(stderr, "\n");
        }
      }
    }
#endif
  }
#ifdef HOST_DEBUG
  fprintf(stderr, "  setup bytes=%d book_end=%d books=%d dim0=%d ent0=%d floor=%d res=%d map=%d mode=%d\n",
          pos, book_end, nb, dim, ent, floors, res, maps, modes);
#endif
  (void)w;
  (void)ex;
  return pos;
}

static int dest_copy_pages(Range *hdr, uint8_t *mem, Writer *w, uint16_t *lace_term, uint32_t gran_base,
                           const uint8_t *src, uint32_t srcn, const PageH *first, uint32_t serial) {
  if (!src || srcn < 27) return -1;
  const uint8_t *audio = 0;
  uint32_t audion = 0;
  uint32_t pos = 0;
  while (pos + 27 <= srcn) {
    if (src[pos] != 'O' || src[pos + 1] != 'g') break;
    uint32_t nseg = src[pos + 26];
    uint32_t hsz = 27 + nseg;
    if (pos + hsz > srcn) break;
    uint32_t body = 0;
    for (uint32_t i = 0; i < nseg; i++) body += src[pos + 27 + i];
    uint32_t tot = hsz + body;
    if (pos + tot > srcn) break;
    uint8_t ptype = body ? src[pos + hsz] : 0;
    if (ptype == 3 || ptype == 5) {
      uint8_t *page = (uint8_t *)malloc(tot);
      if (!page) return -1;
      memcpy(page, src + pos, tot);
      rewrite_serial(page, tot, serial);
      if (emit(w, page, tot) < 0) {
        free(page);
        return -1;
      }
      free(page);
    } else if (ptype != 1) {
      audio = src + pos + hsz;
      audion = srcn - (pos + hsz);
      break;
    }
    pos += tot;
  }
  if (!audio || audion == 0) {
    audio = src;
    audion = srcn;
  }
  uint32_t off = 0;
  auto take = [&](const PageH *h) -> int {
    uint32_t n = (uint32_t)h->body;
    uint8_t *body = (uint8_t *)malloc(n ? n : 1);
    if (!body) return -1;
    for (uint32_t i = 0; i < n; i++) body[i] = audio[(off + i) % audion];
    off += n;
    int rc = emit_pageh(w, h, body);
    free(body);
    return rc;
  };
  if (first && take(first) < 0) return -1;
  if (first && (first->flags & 4)) return 0;
  for (int page = 0; page < 1 << 20; page++) {
    PageH h;
    if (decode_page(hdr, mem, lace_term, 0, gran_base, &h) < 0) break;
    if (take(&h) < 0) return -1;
    if (h.flags & 4) break;
  }
  return 0;
}

static int decode_body(Range *hdr, Range *bod, uint8_t *mem, Writer *w, uint16_t *ctrl, Range *cmd,
                       int books_stat, DecCtx *cx) {
  PageH ident_h;
  if (decode_page(hdr, mem, cx ? cx->lace_term : 0, 2, 0, &ident_h) < 0) {
#ifdef HOST_DEBUG
    fprintf(stderr, "  ident 167c0 fail hdr_left=%ld err=%d\n", (long)(hdr->end - hdr->ptr),
            hdr->err);
#endif
    return -1;
  }
#ifdef HOST_DEBUG
  fprintf(stderr, "  167c0 ht=%d g=%llu ser=%u seq=%u nse=%d body=%d\n", ident_h.flags,
          (unsigned long long)ident_h.granule, ident_h.serial, ident_h.sequence, ident_h.npackets,
          ident_h.body);
#endif

  uint8_t ident[30];
  memset(ident, 0, sizeof(ident));
  ident[0] = 1;
  memcpy(ident + 1, "vorbis", 6);
  int ch = (int)slot_predict(model_at(mem, 9), slot_integer(bod, model_at(mem, 9), 2, 1, 1, 0), 1);
  int rate = (int)slot_predict(model_at(mem, 10), slot_integer(bod, model_at(mem, 10), 5, 1, 4, 0), 1);
  int bmax = (int)slot_predict(model_at(mem, 11), slot_integer(bod, model_at(mem, 11), 5, 1, 4, 0), 1);
  int bnom = (int)slot_predict(model_at(mem, 12), slot_integer(bod, model_at(mem, 12), 5, 1, 4, 0), 1);
  int bmin = (int)slot_predict(model_at(mem, 13), slot_integer(bod, model_at(mem, 13), 5, 1, 4, 0), 1);
  int blks = (int)slot_predict(model_at(mem, 14), slot_integer(bod, model_at(mem, 14), 3, 1, 4, 0), 1);
  int fram = (int)slot_predict(model_at(mem, 15), slot_integer(bod, model_at(mem, 15), 3, 1, 4, 0), 1);
#ifdef HOST_DEBUG
  fprintf(stderr, "  ident ch=%d rate=%d br=%d/%d/%d blk=%d fr=%d\n", ch, rate, bmax, bnom, bmin,
          blks, fram);
#endif
  // PE 046d0 writes the 123b0/signed values. Do not replace rate with 44100.
  if (ch < 1) ch = 1;
  if (ch > 255) ch = 255;
  ident[11] = (uint8_t)ch;
  put_le32(ident + 12, (uint32_t)rate);
  put_le32(ident + 16, (uint32_t)(bmax == (int)0x80000000 ? 0 : bmax));
  put_le32(ident + 20, (uint32_t)(bnom == (int)0x80000000 ? 0 : bnom));
  put_le32(ident + 24, (uint32_t)(bmin == (int)0x80000000 ? 0 : bmin));
  {
    int b = blks;
    if (b == (int)0x80000000 || b == 0) b = (8 << 4) | 11;
    ident[28] = (uint8_t)b;
  }
  ident[29] = 1;
#ifdef HOST_DEBUG
  fprintf(stderr, "  ident hex=");
  for (int i = 0; i < 30; i++) fprintf(stderr, "%02x", ident[i]);
  fprintf(stderr, "\n");
#endif
  uint32_t serial = ident_h.serial ? ident_h.serial : 1;
  uint32_t seq = 0;
  if (ident_h.npackets == 1 && ident_h.packets[0] == 30) {
    if (emit_pageh(w, &ident_h, ident) < 0) return -1;
    seq = ident_h.sequence + 1;
  } else {
    PageH ih = ident_h;
    ih.flags = 2;
    ih.sequence = 0;
    ih.npackets = 1;
    ih.nlacing = 1;
    ih.lacing[0] = 30;
    ih.body = 30;
    if (emit_pageh(w, &ih, ident) < 0) return -1;
    seq = 1;
  }

  uint8_t *amodel = (uint8_t *)calloc(1, 0x6e000);
  if (!amodel) return -1;
  for (int s = 0; s < 0x37; s++)
    init_freq((uint16_t *)(amodel + s * 0x2000 + 0x0c), (0x2000 - 0x0c) / 2);
  AudioSt ast = {};
  ast.mem = amodel;
  ast.memsz = 0x6e000;
  ast.nch = ch;

  int used_cache = 0;
  int dest_copied = 0;
  uint32_t header_mark = w->pos;
  if (cmd && ctrl && getbit(cmd, &ctrl[10]) == 1) {
    uint32_t back = slot_integer(cmd, model_at(mem, 53), 5, 0, 2, 1);
    int n = cx ? cx->nheaders : 0;
#ifdef HOST_DEBUG
    fprintf(stderr, "  cache back=%u of %d\n", back, n);
#endif
    if (!cx || n <= 0 || back >= (uint32_t)n) {
      free(amodel);
      return -1;
    }
    int index = n - 1 - (int)back;
    HdrEnt *ent = &cx->headers[index];
    uint8_t *pages = (uint8_t *)malloc(ent->n ? ent->n : 1);
    if (!pages) {
      free(amodel);
      return -1;
    }
    if (ent->n) memcpy(pages, ent->pages, ent->n);
    rewrite_serial(pages, ent->n, serial);
    if (emit(w, pages, ent->n) < 0) {
      free(pages);
      free(amodel);
      return -1;
    }
    free(pages);
    ast_clone_setup(&ast, &ent->ast);
    ast.mem = amodel;
    ast.memsz = 0x6e000;
    ast.nch = ch;
    if (cx) ast_clone_setup(&cx->last_cached.ast, &ent->ast);
    used_cache = 1;
    header_mark = w->pos;
  } else {
    PageH hdr_h;
    if (decode_page(hdr, mem, cx ? cx->lace_term : 0, 0, 0, &hdr_h) < 0) {
      free(amodel);
      return -1;
    }
#ifdef HOST_DEBUG
    fprintf(stderr, "  hdrpage n=%d body=%d flags=%02x\n", hdr_h.npackets, hdr_h.body, hdr_h.flags);
#endif
    if (hdr_h.npackets != 2) {
      const uint8_t *src = cx ? cx->last_stream : 0;
      uint32_t srcn = cx ? cx->last_n : 0;
      if (dest_copy_pages(hdr, mem, w, cx ? cx->lace_term : 0, 0, src, srcn, &hdr_h, serial) < 0) {
        free(amodel);
        return -1;
      }
      dest_copied = 1;
#ifdef HOST_DEBUG
      fprintf(stderr, "  destcopy out+=%u\n", w->pos);
#endif
    } else {
      uint8_t comm_len_slot[0x2000];
      uint8_t comm_byte_slot[0x2000];
      memset(comm_len_slot, 0, sizeof(comm_len_slot));
      memset(comm_byte_slot, 0, sizeof(comm_byte_slot));
      init_freq((uint16_t *)(comm_len_slot + 0x0c), (0x2000 - 0x0c) / 2);
      init_freq((uint16_t *)(comm_byte_slot + 0x0c), (0x2000 - 0x0c) / 2);
      int clen = hdr_h.packets[0];
      uint8_t *commb = (uint8_t *)malloc((size_t)clen + 1);
      if (!commb) {
        free(amodel);
        return -1;
      }
      memset(commb, 0, (size_t)clen + 1);
      int prev = 0;
      for (int i = 0; i < clen; i++) {
        int b = dec_a790_byte(bod, comm_byte_slot);
        commb[i] = (uint8_t)(b < 0 ? 0 : b);
        prev = commb[i];
      }
      (void)prev;
      Extra ex = {};
      uint8_t *setup = (uint8_t *)malloc(1 << 20);
      if (!setup) {
        free(commb);
        free(amodel);
        return -1;
      }
      int nbooks = 0;
      int slen = decode_setup(bod, mem, setup, 1 << 20, &nbooks, 0, w, &ex, &ast);
      if (slen < 0) slen = 0;
      if (slen > hdr_h.packets[1]) slen = hdr_h.packets[1];
      uint32_t pay = (uint32_t)(clen + hdr_h.packets[1]);
      uint8_t *body = (uint8_t *)calloc(1, pay ? pay : 1);
      if (!body) {
        free(setup);
        free(commb);
        free(amodel);
        return -1;
      }
      memcpy(body, commb, (size_t)clen);
      if (slen > 0) memcpy(body + clen, setup, (size_t)slen);
      emit_pageh(w, &hdr_h, body);
      if (cmd && ctrl && getbit(cmd, &ctrl[14]) == 1 && cx && cx->nheaders < 32) {
        HdrEnt *ent = &cx->headers[cx->nheaders];
        uint32_t hn = w->pos - header_mark;
        ent->pages = (uint8_t *)malloc(hn ? hn : 1);
        if (ent->pages) {
          if (hn) memcpy(ent->pages, w->dst + header_mark, hn);
          ent->n = hn;
          ast_clone_setup(&ent->ast, &ast);
          cx->nheaders++;
        }
#ifdef HOST_DEBUG
        fprintf(stderr, "  newhdr store=1 headers=%d pay=%u\n", cx->nheaders, hn);
#endif
      }
#ifdef HOST_DEBUG
      else
        fprintf(stderr, "  newhdr store=0 clen=%d slen=%d\n", clen, slen);
#endif
      if (cx) ast_clone_setup(&cx->last_cached.ast, &ast);
      free(body);
      free(setup);
      free(commb);
    }
  }
  (void)books_stat;
  (void)seq;
  if (dest_copied) {
    books_free(&ast.books);
    free(amodel);
    return 0;
  }

  // Extra = reconstructed dest (1,0 window / solid books-stat).
  Extra headers = {};
  headers.ptr = w->dst;
  headers.end = w->dst + w->pos;
  headers.nbits = 0;
  uint32_t header_end = w->pos;
  Extra walk = headers;
  int npkt = 0, nfile = 1, nextra = 0, nbig = 0, nskip = 0, nmulti = 0;
#ifdef HOST_DEBUG
  int nse0_ht[8] = {}, nse0_cont = 0, nse0_nocont = 0;
#endif
  uint64_t raw_body_sum = 0;
  uint64_t gran = 0;
  int last_need_cont = 0;
  int last_lace0 = 0;
  int last_skipz_n1 = 0;
  int last_skipz_ht = 0;
  int n_h0z = 0;
  int nbody_pages = 0;
  PktStream pstream = {};
  int ht = 0, g0 = 0, g1 = 0, ser = 0, seqn = 0, nse = 0, body = 0;
  for (;;) {
    PageH ah;
    if (decode_page(hdr, mem, cx ? cx->lace_term : 0, 0, 0, &ah) < 0) break;
    ht = ah.flags;
    g0 = (int)(uint32_t)ah.granule;
    g1 = (int)(ah.granule >> 32);
    ser = (int)ah.serial;
    seqn = (int)ah.sequence;
    nse = ah.npackets;
    body = ah.body;
    uint8_t *pkt = 0;
    if (body > 0) {
      pkt = (uint8_t *)calloc(1, (size_t)body);
      if (!pkt) break;
      emit_02790_dest(bod, &ast, &pstream, pkt, body, ast.nch > 0 ? ast.nch : ch, 1);
    }
#ifdef HOST_DEBUG
    raw_body_sum += (uint64_t)(body > 0 ? body : 0);
    if (body > 65025) nbig++;
    if (nse > 1) nmulti++;
    if (npkt < 8)
      fprintf(stderr, "  audio%d ht=%d nse=%d body=%d ser=%u seq=%u eos=%d hdr_in=%ld\n", npkt, ht,
              nse, body, ah.serial, ah.sequence, (ht & 4) != 0, (long)(hdr->end - hdr->ptr));
#endif
    if (emit_pageh(w, &ah, pkt) < 0) {
      free(pkt);
      break;
    }
    free(pkt);
    npkt++;
    nbody_pages++;
    if (ht & 4) break;
    if (nbody_pages >= 37753) break;
    if (w->pos >= kDestCap) break;
  }
#ifdef HOST_DEBUG
  {
    long bod_win = (long)(bod->end - bod->ptr);
    long bod_src = (bod->src && bod->src_end) ? (long)(bod->src_end - bod->src) : 0;
    fprintf(stderr, "  audio pages=%d files=%d extra=%d hdr_end=%u hdr_in=%ld bod leftover %ld (win=%ld src=%ld) out=%u raw_body=%llu nbig=%d nskip=%d nmulti=%d\n",
            npkt, nfile, nextra, header_end, (long)(hdr->end - hdr->ptr), bod_win + bod_src, bod_win,
            bod_src, w->pos, (unsigned long long)raw_body_sum, nbig, nskip, nmulti);
  }
  fprintf(stderr, "  nse0 cont=%d nocont=%d h0z=%d ht0-7=%d %d %d %d %d %d %d %d\n", nse0_cont,
          nse0_nocont, n_h0z,
          nse0_ht[0], nse0_ht[1], nse0_ht[2], nse0_ht[3], nse0_ht[4], nse0_ht[5], nse0_ht[6],
          nse0_ht[7]);
  fprintf(stderr, "  copy ok=%llu fail=%llu trunc=%llu want=%llu got=%llu\n",
          (unsigned long long)gCopyOk, (unsigned long long)gCopyFail, (unsigned long long)gCopyTrunc,
          (unsigned long long)gCopyWant, (unsigned long long)gCopyGot);
  fprintf(stderr, "  write_book bit1=%llu res_run=%llu calls=%llu bits=%llu nz_codes=%llu\n",
          (unsigned long long)gBit1, (unsigned long long)gResRun, (unsigned long long)gWbCalls,
          (unsigned long long)gWbBits, (unsigned long long)gWbNz);
#endif
  (void)header_end;
  (void)nbig;
  (void)nskip;
  (void)nmulti;
  (void)n_h0z;
  books_free(&ast.books);
  free(amodel);
  return 0;
}

// 0x10019d10: low two bits are the following-byte count, not the size.
struct Cursor {
  const uint8_t *p, *end;
};

static int read_size(Cursor *c, uint32_t *out) {
  if (!c || c->p >= c->end) return -1;
  uint8_t b[4] = {0, 0, 0, 0};
  b[0] = *c->p++;
  int n = b[0] & 3;
  for (int i = 0; i < n; i++) {
    if (c->p >= c->end) return -1;
    b[i + 1] = *c->p++;
  }
  *out = (uint32_t)(b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >> 2;
  return 0;
}

static int read_frame(Cursor *c, const uint8_t **data, uint32_t *len) {
  uint32_t n = 0;
  if (read_size(c, &n) < 0) return -1;
  if (n > (512u << 20) || (uint32_t)(c->end - c->p) < n) return -1;
  *data = c->p;
  *len = n;
  c->p += n;
  return 0;
}

static int range_from_bytes(Range *r, const uint8_t *p, uint32_t n) {
  memset(r, 0, sizeof(*r));
  r->ptr = p;
  r->end = p + n;
  r->range = 0xffffffffu;
  r->code = 0;
  for (int i = 0; i < 4; i++) {
    if (r->ptr >= r->end) return -1;
    r->code = (r->code << 8) | *r->ptr++;
  }
  return 0;
}

static int32_t decode(const uint8_t *src, uint32_t slen, uint8_t *dst, uint32_t dcap) {
  if (!src || !dst || slen < 7 || dcap == 0) return 0;
  if (src[0] != 'O' || src[1] != 'G' || src[2] != 'G' || src[3] != 'R' || src[4] != 'E') return 0;
  if (src[5] != 0) return 0;
  uint8_t flags = src[6];
  if ((flags & 7) > 3) return 0;
  crc_init();

  Cursor cur = {src + 7, src + slen};
  const uint8_t *cmdp = 0;
  uint32_t cmdn = 0;
  if (read_frame(&cur, &cmdp, &cmdn) < 0) return 0;
  Range cmd;
  if (range_from_bytes(&cmd, cmdp, cmdn) < 0) return 0;

  uint16_t ctrl[18];
  init_freq(ctrl, 18);
  uint8_t *mem = (uint8_t *)calloc(1, 0x6e000);
  if (!mem) return 0;
  for (int s = 0; s < 0x37; s++) {
    uint16_t *p = (uint16_t *)(mem + s * 0x2000 + 0x0c);
    init_freq(p, (0x2000 - 0x0c) / 2);
  }

  Writer w = {dst, dcap, 0};
  const uint8_t *stored[32] = {};
  uint32_t storedn[32] = {};
  int nstore = 0;
  uint32_t previous = 0;
  uint16_t lace_term = 0x8000;
  DecCtx cx = {};
  cx.cmd = &cmd;
  cx.ctrl = ctrl;
  cx.lace_term = &lace_term;
  static const int kSolidReset[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23, 27, 28, 29, 30};
  for (int rec = 0; rec < 1 << 16; rec++) {
    int b0 = getbit(&cmd, &ctrl[previous]);
    if (b0 < 0) break;
    previous = (uint32_t)b0;
    if (b0 == 0) {
      const uint8_t *raw = 0;
      uint32_t rawn = 0;
      if (read_frame(&cur, &raw, &rawn) < 0) break;
      if (w.pos + rawn > w.cap) break;
      memcpy(w.dst + w.pos, raw, rawn);
      w.pos += rawn;
      cx.last_stream = w.dst + (w.pos - rawn);
      cx.last_n = rawn;
      continue;
    }
    int b1 = getbit(&cmd, &ctrl[2]);
    if (b1 < 0) break;
    if (b1 != 0) {
      uint32_t back = slot_integer(&cmd, model_at(mem, 52), 5, 0, 2, 1);
      if (nstore <= 0) break;
      int index = nstore - 1 - (int)(back % (uint32_t)nstore);
      if (index < 0) index += nstore;
      uint32_t n = storedn[index];
      if (w.pos + n > w.cap) break;
      memcpy(w.dst + w.pos, stored[index], n);
      cx.last_stream = w.dst + w.pos;
      cx.last_n = n;
      w.pos += n;
#ifdef HOST_DEBUG
      fprintf(stderr, "rec %d replay back=%u idx=%d n=%u total=%u\n", rec, back, index, n, w.pos);
#endif
      continue;
    }
    int store = getbit(&cmd, &ctrl[6]);
    if (store < 0) break;
    const uint8_t *fp[3];
    uint32_t fn[3];
    int ok = 1;
    for (int i = 0; i < 3; i++) {
      if (read_frame(&cur, &fp[i], &fn[i]) < 0) {
        ok = 0;
        break;
      }
    }
    if (!ok) break;
    if (flags & 8) {
      for (int i : kSolidReset) memset(model_at(mem, i), 0, 12);
    } else {
      for (int i = 0; i < 52; i++) {
        memset(model_at(mem, i), 0, 12);
        init_freq((uint16_t *)(model_at(mem, i) + 12), (0x2000 - 12) / 2);
      }
      lace_term = 0x8000;
    }
    Range hdr, bod;
    if (range_from_bytes(&hdr, fp[1], fn[1]) < 0) break;
    if (range_from_bytes(&bod, fp[2], fn[2]) < 0) break;
    uint32_t before = w.pos;
    decode_body(&hdr, &bod, mem, &w, ctrl, &cmd, (int)(flags & 7), &cx);
    uint32_t produced = w.pos - before;
    if (produced > 0) {
      cx.last_stream = w.dst + before;
      cx.last_n = produced;
    }
    if (store && nstore < 32) {
      uint8_t *cp = (uint8_t *)malloc(produced ? produced : 1);
      if (cp) {
        if (produced) memcpy(cp, w.dst + before, produced);
        stored[nstore] = cp;
        storedn[nstore] = produced;
        nstore++;
      }
    }
#ifdef HOST_DEBUG
    fprintf(stderr, "rec %d store=%d out+=%u total=%u headers=%d\n", rec, store, produced, w.pos,
            cx.nheaders);
#endif
  }
  for (int i = 0; i < nstore; i++) free((void *)stored[i]);
  for (int i = 0; i < cx.nheaders; i++) {
    free(cx.headers[i].pages);
    ast_clear_books(&cx.headers[i].ast);
  }
  ast_clear_books(&cx.last_cached.ast);
  free(mem);
  return (int32_t)w.pos;
}

} // namespace

extern "C" int32_t mpzz_decode(uint8_t *src, uint32_t slen, uint8_t *dst, uint32_t dcap) {
  return decode(src, slen, dst, dcap);
}

#ifdef HOST_DEBUG
int main(int argc, char **argv) {
  const char *path = argc > 1 ? argv[1] : "/tmp/gf-extract/fg01-after-srep.bin";
  FILE *f = fopen(path, "rb");
  if (!f) {
    perror(path);
    return 1;
  }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t *src = (uint8_t *)malloc((size_t)n);
  if (!src || fread(src, 1, (size_t)n, f) != (size_t)n) {
    fprintf(stderr, "read failed\n");
    return 1;
  }
  fclose(f);
  if (argc > 2 && strcmp(argv[2], "scan") == 0) {
    uint8_t *mem = (uint8_t *)calloc(1, 0x6e000);
    if (!mem) return 1;
    for (int s = 0; s < 0x37; s++)
      init_freq((uint16_t *)(mem + s * 0x2000 + 0x0c), (0x2000 - 0x0c) / 2);
    for (uint32_t off = 0; off <= 64; off++) {
      Range bod;
      if (range_init_window(&bod, src, (uint32_t)n, off) < 0) continue;
      int ch = range_dec_signed_2(&bod, mem + 0x12000, 0);
      int rate = range_dec_signed_5(&bod, mem + 0x14000, 0);
      int clen = dec_u5(&bod, mem + 0x6a000);
      int hit = (ch >= 1 && ch <= 8 && rate >= 8000 && rate <= 192000);
      if (hit || off < 16 || off == 7)
        fprintf(stderr, "off=%u ch=%d rate=%d vendor=%d%s\n", off, ch, rate, clen, hit ? " HIT" : "");
      // reset ident slots
      for (int s = 9; s <= 15; s++) {
        memset(mem + s * 0x2000, 0, 0x0c);
        init_freq((uint16_t *)(mem + s * 0x2000 + 0x0c), (0x2000 - 0x0c) / 2);
      }
      init_freq((uint16_t *)(mem + 0x6a000 + 0x0c), (0x2000 - 0x0c) / 2);
      memset(mem + 0x6a000, 0, 0x0c);
      free(bod.win);
    }
    free(mem);
    free(src);
    return 0;
  }
  uint32_t cap = kDestCap;
  uint8_t *dst = (uint8_t *)malloc(cap);
  if (!dst) return 1;
  int32_t got = mpzz_decode(src, (uint32_t)n, dst, cap);
  uint32_t crc = 0;
  if (got > 0) {
    static uint32_t ieee[256];
    for (uint32_t i = 0; i < 256; i++) {
      uint32_t c = i;
      for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0xedb88320u & -(c & 1));
      ieee[i] = c;
    }
    crc = 0xffffffffu;
    for (int32_t i = 0; i < got; i++) crc = ieee[(crc ^ dst[i]) & 0xff] ^ (crc >> 8);
    crc ^= 0xffffffffu;
  }
  if (got > 0) {
    FILE *df = fopen("/tmp/oggre-out.bin", "wb");
    if (df) {
      fwrite(dst, 1, (size_t)got, df);
      fclose(df);
    }
  }
  fprintf(stderr, "size %d want %u crc %08x want %08x head ", got, kWant, crc, kWantCRC);
  for (int i = 0; i < 32 && i < got; i++) fprintf(stderr, "%02x", dst[i]);
  fprintf(stderr, "\n");
  int ok = (uint32_t)got == kWant && crc == kWantCRC;
  free(src);
  free(dst);
  return ok ? 0 : 2;
}
#endif
