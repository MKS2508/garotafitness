// Faithful port of stream/mpzz Go decoder (entropy, page, setup, audio,
// residue, command loop). INV-03: no PE exec. No threads.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <array>
#include <vector>
#include <map>
#include <algorithm>

namespace {

struct Range {
  const uint8_t *data;
  int pos, tail, len;
  uint32_t code, width;
  int err;
};

struct Model {
  uint32_t value, delta, nonzero, sign, length;
  uint16_t prob[4090];
};

static void model_reset(Model *m) {
  m->value = m->delta = m->nonzero = m->sign = m->length = 0;
  for (int i = 0; i < 4090; i++) m->prob[i] = 0x8000;
}

static uint32_t range_bit(Range *r, uint16_t *p) {
  if (r->err) return 0;
  while (r->width < (1u << 24)) {
    uint8_t next;
    if (r->pos >= r->len) {
      if (r->tail == 4) {
        r->err = 1;
        return 0;
      }
      r->tail++;
      next = r->data[r->len - 1];
    } else {
      next = r->data[r->pos++];
    }
    r->code = (r->code << 8) | next;
    r->width <<= 8;
  }
  uint32_t f = *p;
  uint32_t bound = (r->width >> 16) * f;
  if (r->code >= bound) {
    r->code -= bound;
    r->width -= bound;
    *p = (uint16_t)(f - (f >> 6));
    return 1;
  }
  r->width = bound;
  *p = (uint16_t)(f + ((65535 - f) >> 6));
  return 0;
}

static uint32_t pbit(Range *r, std::vector<uint16_t> *probs, int idx) {
  if (!probs || idx < 0 || idx >= (int)probs->size()) {
    r->err = 1;
    return 0;
  }
  return range_bit(r, &(*probs)[idx]);
}

static void range_init(Range *r, const uint8_t *d, int n) {
  memset(r, 0, sizeof(*r));
  r->data = d;
  r->len = n;
  r->width = 0xffffffffu;
  if (n == 0) {
    r->err = 1;
    return;
  }
  int k = n < 4 ? n : 4;
  for (int i = 0; i < k; i++) r->code |= (uint32_t)d[i] << (24 - 8 * i);
  r->pos = k;
}

static uint32_t model_bit(Model *m, Range *r, uint32_t off) {
  if (off < 12 || (off & 1) || off >= 0x2000) {
    r->err = 1;
    return 0;
  }
  return range_bit(r, &m->prob[(off - 12) / 2]);
}

static uint32_t model_int(Model *m, Range *r, uint32_t length_bits, uint32_t sign_bits, uint32_t low_bits,
                          int grouped) {
  uint32_t b = model_bit(m, r, 12 + 2 * m->nonzero);
  m->nonzero = (2 * m->nonzero + b) & 3;
  if (b == 0) {
    m->length = 0;
    return 0;
  }
  uint32_t sign = 0;
  if (sign_bits) {
    sign = model_bit(m, r, 20 + 2 * m->sign);
    m->sign = (2 * m->sign + sign) & ((1u << sign_bits) - 1);
  }
  uint32_t base = 0x34 + (m->length << (length_bits + 1));
  uint32_t v = 1;
  for (uint32_t i = 0; i < length_bits; i++) v = 2 * v + model_bit(m, r, base + 2 * v);
  uint32_t n = v & ((1u << length_bits) - 1);
  m->length = n + 1;
  base = 0x834;
  if (grouped) base += n << (low_bits + 1);
  v = 1;
  uint32_t ctx = 1;
  for (uint32_t i = 0; i < n; i++) {
    b = model_bit(m, r, base + 2 * ctx);
    v = 2 * v + b;
    if (ctx < (1u << (low_bits - 1))) ctx = (2 * ctx + b) & ((1u << low_bits) - 1);
  }
  return (v ^ (0u - sign)) + sign;
}

static uint32_t model_pred(Model *m, uint32_t v, int order) {
  if (order >= 2) {
    m->delta += v;
    v = m->delta;
  }
  if (order >= 1) {
    m->value += v;
    v = m->value;
  }
  return v;
}

static uint32_t ogg_crc(const uint8_t *p, int n) {
  uint32_t crc = 0;
  for (int i = 0; i < n; i++) {
    crc ^= (uint32_t)p[i] << 24;
    for (int j = 0; j < 8; j++) {
      if (crc & 0x80000000u)
        crc = crc << 1 ^ 0x04c11db7u;
      else
        crc <<= 1;
    }
  }
  return crc;
}

struct Page {
  uint8_t flags;
  uint64_t granule;
  uint32_t serial, sequence;
  std::vector<int> packets;
  std::vector<uint8_t> lacing;
};

static int emit_page(std::vector<uint8_t> *out, const Page *h, uint8_t flags, uint32_t seq,
                     const uint8_t *lacing, int nlace, const uint8_t *body, int nbody) {
  if (nlace > 255) return -1;
  int hsz = 27 + nlace;
  std::vector<uint8_t> p(hsz + nbody);
  p[0] = 'O';
  p[1] = 'g';
  p[2] = 'g';
  p[3] = 'S';
  p[5] = flags;
  for (int i = 0; i < 8; i++) p[6 + i] = (uint8_t)(h->granule >> (8 * i));
  p[14] = (uint8_t)h->serial;
  p[15] = (uint8_t)(h->serial >> 8);
  p[16] = (uint8_t)(h->serial >> 16);
  p[17] = (uint8_t)(h->serial >> 24);
  p[18] = (uint8_t)seq;
  p[19] = (uint8_t)(seq >> 8);
  p[20] = (uint8_t)(seq >> 16);
  p[21] = (uint8_t)(seq >> 24);
  p[26] = (uint8_t)nlace;
  if (nlace) memcpy(&p[27], lacing, nlace);
  if (nbody) memcpy(&p[hsz], body, nbody);
  uint32_t crc = ogg_crc(p.data(), hsz + nbody);
  p[22] = (uint8_t)crc;
  p[23] = (uint8_t)(crc >> 8);
  p[24] = (uint8_t)(crc >> 16);
  p[25] = (uint8_t)(crc >> 24);
  out->insert(out->end(), p.begin(), p.end());
  return 0;
}

static int marshal_page(std::vector<uint8_t> *out, const Page *h, const uint8_t *body, int nbody) {
  int size = 0;
  for (uint8_t v : h->lacing) size += v;
  if (size != nbody) return -1;
  if ((int)h->lacing.size() <= 255)
    return emit_page(out, h, h->flags, h->sequence, h->lacing.data(), (int)h->lacing.size(), body, nbody);
  uint32_t seq = h->sequence;
  uint8_t flags = h->flags;
  int li = 0, boff = 0;
  std::vector<uint8_t> segs;
  int pay = 0;
  auto flush = [&](int last) -> int {
    uint8_t f = flags & ~4;
    if (last) f = flags;
    if (emit_page(out, h, f, seq, segs.data(), (int)segs.size(), body + boff, pay) < 0) return -1;
    if (!segs.empty() && segs.back() == 255)
      flags = (flags & ~2) | 1;
    else
      flags = flags & ~3;
    seq++;
    boff += pay;
    segs.clear();
    pay = 0;
    return 0;
  };
  for (size_t i = 0; i < h->packets.size(); i++) {
    int start = li;
    int sl = h->packets[i];
    if (sl == 0) {
      li++;
    } else {
      while (sl > 0 && li < (int)h->lacing.size()) {
        sl -= h->lacing[li];
        li++;
      }
      if (i + 1 == h->packets.size() && li < (int)h->lacing.size()) li++;
    }
    while (start < li) {
      int take = li - start;
      int room = 255 - (int)segs.size();
      if (room == 0) {
        if (flush(0) < 0) return -1;
        room = 255;
      }
      if (take > room) take = room;
      segs.insert(segs.end(), h->lacing.begin() + start, h->lacing.begin() + start + take);
      for (int k = 0; k < take; k++) pay += h->lacing[start + k];
      start += take;
    }
  }
  return flush(1);
}

// laces=0: 167c0(a1!=0) — flags/granule/serial/seq/n only; dest supplies laces.
static int decode_page_ex(Range *r, Model *models, uint16_t *terminal, uint8_t xor_flags, uint32_t gran_base,
                          Page *h, int laces) {
  h->packets.clear();
  h->lacing.clear();
  h->flags = (uint8_t)(model_int(&models[0], r, 3, 0, 2, 0) ^ xor_flags);
  uint32_t lo = model_pred(&models[1], model_int(&models[1], r, 5, 2, 4, 0), 1) + gran_base;
  uint32_t hi = model_pred(&models[2], model_int(&models[2], r, 5, 1, 1, 0), 1);
  h->granule = ((uint64_t)hi << 32) | lo;
  h->serial = model_pred(&models[3], model_int(&models[3], r, 5, 2, 4, 0), 1);
  h->sequence = model_pred(&models[4], model_int(&models[4], r, 5, 2, 4, 0), 2);
  uint32_t n = model_int(&models[5], r, 3, 0, 4, 1);
  if (n > 255) {
#ifdef HOST_DEBUG
    fprintf(stderr, "  167c0 n=%u flags=%02x ser=%u err=%d\n", n, h->flags, h->serial, r->err);
#endif
    return -1;
  }
  if (!laces) {
    h->packets.assign((int)n, 0);
    return r->err ? -1 : 0;
  }
  for (uint32_t i = 0; i < n; i++) {
    uint32_t size = model_int(&models[6], r, 4, 0, 6, 1);
    if (size > (16u << 20)) return -1;
    h->packets.push_back((int)size);
    while (size >= 255) {
      h->lacing.push_back(255);
      size -= 255;
    }
    int term = 0;
    if (size == 0 && i + 1 >= n) term = (int)range_bit(r, terminal);
    if (size != 0 || i + 1 < n || term) h->lacing.push_back((uint8_t)size);
  }
  return r->err ? -1 : 0;
}

static int decode_page(Range *r, Model *models, uint16_t *terminal, uint8_t xor_flags, uint32_t gran_base,
                       Page *h) {
  return decode_page_ex(r, models, terminal, xor_flags, gran_base, h, 1);
}

static int fill_laces(Range *r, Model *models, uint16_t *terminal, Page *h) {
  uint32_t n = (uint32_t)h->packets.size();
  h->packets.clear();
  h->lacing.clear();
  for (uint32_t i = 0; i < n; i++) {
    uint32_t size = model_int(&models[6], r, 4, 0, 6, 1);
    if (size > (16u << 20)) return -1;
    h->packets.push_back((int)size);
    while (size >= 255) {
      h->lacing.push_back(255);
      size -= 255;
    }
    int term = 0;
    if (size == 0 && i + 1 >= n) term = (int)range_bit(r, terminal);
    if (size != 0 || i + 1 < n || term) h->lacing.push_back((uint8_t)size);
  }
  return r->err ? -1 : 0;
}

struct BitW {
  std::vector<uint8_t> data;
  uint32_t n;
  void write(uint32_t v, uint32_t bits) {
    for (uint32_t i = 0; i < bits; i++) {
      if ((n & 7) == 0) data.push_back(0);
      data.back() |= (uint8_t)((v & 1) << (n & 7));
      v >>= 1;
      n++;
    }
  }
};

static int bit_len(uint32_t v) {
  int n = 0;
  while (v) {
    v >>= 1;
    n++;
  }
  return n;
}

static uint32_t rev32(uint32_t x) {
  uint32_t r = 0;
  for (int i = 0; i < 32; i++) r = r << 1 | (x >> i & 1);
  return r;
}

struct Codebook {
  int dim, lookup, context, radix;
  std::vector<uint8_t> lengths;
  std::vector<uint32_t> codes;
  std::vector<int> quant;
  uint32_t delta;
  std::map<int, int> symbols;
};

static int build_codes(Codebook *b) {
  int e = (int)b->lengths.size();
  b->codes.assign(e, 0);
  uint32_t available[33] = {};
  int first = 1;
  for (int i = 0; i < e; i++) {
    int length = b->lengths[i];
    if (!length) continue;
    if (length > 32) return -1;
    if (first) {
      first = 0;
      for (int n = 1; n <= length; n++) available[n] = 1u << (32 - n);
      continue;
    }
    int n = length;
    while (n > 0 && available[n] == 0) n--;
    if (n == 0) return -1;
    uint32_t code = available[n];
    available[n] = 0;
    b->codes[i] = rev32(code);
    for (n++; n <= length; n++) available[n] = code + (1u << (32 - n));
  }
  return 0;
}

static int book_write(const Codebook *b, BitW *w, int symbol) {
  if (symbol < 0 || symbol >= (int)b->lengths.size() || b->lengths[symbol] == 0) return -1;
  w->write(b->codes[symbol], b->lengths[symbol]);
  return 0;
}

static float vorbis_float(uint32_t v) {
  int m = (int)(v & 0x1fffff);
  if (v >> 31) m = -m;
  return (float)ldexp((double)m, (int)((v >> 21) & 0x3ff) - 788);
}

struct CachedBook {
  std::vector<uint8_t> lengths;
  int quant;
  float delta;
  uint32_t uses;
  int used;
};

struct BookCache {
  int capacity;
  std::vector<CachedBook> books;
};

static int lookup_count(int entries, int dim) {
  int lo = 1, hi = entries;
  while (lo < hi) {
    int mid = lo + (hi - lo + 1) / 2;
    int v = 1;
    for (int i = 0; i < dim && v <= entries; i++) {
      if (v > entries / mid) {
        v = entries + 1;
        break;
      }
      v *= mid;
    }
    if (v <= entries)
      lo = mid;
    else
      hi = mid - 1;
  }
  return lo;
}

static int tz_u32(uint32_t x) {
  if (!x) return 32;
  int n = 0;
  while ((x & 1) == 0) {
    x >>= 1;
    n++;
  }
  return n;
}

static int select_book(BookCache *c, Codebook *b, std::vector<uint16_t> *probs) {
  std::vector<uint8_t> lengths = b->lengths;
  uint8_t longest = 0;
  int used = 0;
  for (uint8_t n : lengths) {
    if (n > longest) longest = n;
    if (n) used++;
  }
  uint8_t missing = 0xff;
  if (used < (int)lengths.size() / 4) missing = longest;
  for (size_t i = 0; i < lengths.size(); i++)
    if (lengths[i] == 0) lengths[i] = missing;
  float delta = vorbis_float(b->delta);
  int best = 0;
  uint32_t distance = 0xffffffffu;
  for (size_t i = 0; i < c->books.size(); i++) {
    CachedBook &old = c->books[i];
    if (old.quant != (int)b->quant.size() || old.delta != delta || old.lengths.size() != lengths.size())
      continue;
    uint32_t d = 0;
    for (size_t j = 0; j < lengths.size(); j++) {
      int x = (int)lengths[j] - (int)old.lengths[j];
      if (x < 0) x = -x;
      d += (uint32_t)x;
    }
    if (d < distance) {
      best = (int)i;
      distance = d;
      if (d == 0) break;
    }
  }
  uint32_t score = (distance << 8) / (uint32_t)lengths.size();
  if (score <= 256 && !c->books.empty()) {
    c->books[best].uses++;
    c->books[best].used = 1;
    return best;
  }
  if ((int)c->books.size() < c->capacity) {
    best = (int)c->books.size();
    c->books.push_back(CachedBook{});
  } else {
    if (score >= 4095) {
      best = 0;
      for (size_t i = 0; i < c->books.size(); i++)
        if (c->books[i].uses < c->books[best].uses) best = (int)i;
      int base = 0x9225c + best * 0x45400;
      if (base >= 0 && base + 0x45400 <= (int)probs->size()) {
        for (int i = 0; i < 0x45400; i++) (*probs)[base + i] = 0x8000;
      }
    }
    uint32_t uses = 0;
    for (size_t i = 0; i < c->books.size(); i++)
      if ((int)i != best) uses += c->books[i].uses;
    c->books[best].uses = uses >> tz_u32((uint32_t)c->capacity);
  }
  c->books[best].lengths = lengths;
  c->books[best].quant = (int)b->quant.size();
  c->books[best].delta = delta;
  c->books[best].used = 1;
  return best;
}

static int build_lookup(Codebook *b) {
  if (b->lookup != 1) return b->lookup == 0 ? 0 : -1;
  b->symbols.clear();
  int qn = (int)b->quant.size();
  if (qn == 0) return -1;
  for (int i = 0; i < (int)b->lengths.size(); i++) {
    if (!b->lengths[i]) continue;
    int v = i, key = 0;
    for (int d = 0; d < b->dim; d++) {
      key = key * b->radix + b->quant[v % qn];
      v /= qn;
    }
    b->symbols[key] = i;
  }
  return 0;
}

struct FloorClass {
  int dim, sub, master;
  std::vector<int> books;
};
struct FloorCfg {
  std::vector<int> partitions, x;
  std::vector<FloorClass> classes;
  int mult;
};
struct ResidueCfg {
  int kind, begin, end, size, classbook;
  std::vector<std::array<int, 8>> books;
};
struct MappingCfg {
  std::vector<int> mux, floors, residues;
  std::vector<std::array<int, 2>> coupling;
};
struct ModeCfg {
  int large, mapping;
};
struct VorbisSetup {
  std::vector<Codebook> books;
  std::vector<FloorCfg> floors;
  std::vector<ResidueCfg> residues;
  std::vector<MappingCfg> mappings;
  std::vector<ModeCfg> modes;
};

struct SetupDec {
  Range *r;
  Model *models;
  std::vector<uint16_t> *probs;
  BitW w;
  BookCache *cache;
};

static uint32_t s_int(SetupDec *s, int slot, uint32_t n, uint32_t sign, uint32_t low, int grouped, int order,
                      uint32_t outbits) {
  uint32_t v = model_pred(&s->models[slot], model_int(&s->models[slot], s->r, n, sign, low, grouped), order);
  s->w.write(v, outbits);
  return v;
}

static uint32_t s_tree(SetupDec *s, uint32_t base, uint32_t n, uint32_t outbits) {
  uint32_t v = 1;
  for (uint32_t i = 0; i < n; i++) v = 2 * v + pbit(s->r, s->probs, (int)(base + v));
  v &= (1u << n) - 1;
  s->w.write(v, outbits);
  return v;
}

static uint32_t s_float(SetupDec *s, int which) {
  uint32_t sign = pbit(s->r, s->probs, 0x2250 + which);
  uint32_t exponent = model_pred(&s->models[50 + which], model_int(&s->models[50 + which], s->r, 4, 1, 2, 0), 1);
  uint32_t mantissa = model_pred(&s->models[48], model_int(&s->models[48], s->r, 5, 1, 6, 0), 1);
  uint32_t v = (sign << 31) + (exponent << 21) + mantissa;
  s->w.write(v, 32);
  return v;
}

static int codebooks(SetupDec *s, std::vector<Codebook> *out) {
  s->w.write(5, 8);
  for (int i = 0; i < 6; i++) s->w.write((uint8_t)"vorbis"[i], 8);
  uint32_t n = s_int(s, 16, 3, 1, 4, 1, 1, 8) + 1;
  if (n > 256) return -1;
  out->assign(n, Codebook{});
  for (uint32_t i = 0; i < n; i++) {
    s->w.write(0x564342, 24);
    uint32_t dim = s_int(s, 17, 4, 2, 4, 0, 1, 16);
    uint32_t entries = s_int(s, 18, 5, 0, 6, 1, 0, 24);
    if (dim == 0 || dim > 65535 || entries == 0 || entries > (1u << 20)) return -1;
    Codebook *book = &(*out)[i];
    book->dim = (int)dim;
    book->lengths.assign(entries, 0);
    uint32_t ordered = s_tree(s, 0x2218, 1, 1);
    uint32_t sparse = 0;
    if (ordered == 0) sparse = s_tree(s, 0x221a, 1, 1);
    if (ordered) {
      uint32_t length = s_int(s, 19, 3, 0, 4, 1, 0, 5) + 1;
      for (int filled = 0; filled < (int)entries; length++) {
        if (length > 32) return -1;
        int count = (int)s_int(s, 20, 4, 0, 4, 1, 0, (uint32_t)bit_len(entries - (uint32_t)filled));
        if (count > (int)entries - filled) return -1;
        for (int j = 0; j < count; j++) book->lengths[filled + j] = (uint8_t)length;
        filled += count;
      }
    } else {
      uint32_t prev = 2;
      for (uint32_t j = 0; j < entries; j++) {
        if (sparse) prev = s_tree(s, 0x221c + prev, 1, 1);
        if (prev == 0) continue;
        uint32_t length = s_int(s, 21, 3, 1, 4, 1, 1, 5) + 1;
        if (length > 32) return -1;
        book->lengths[j] = (uint8_t)length;
      }
    }
    book->lookup = (int)s_tree(s, 0x2220, 2, 4);
    if (book->lookup > 2) return -1;
    if (book->lookup) {
      s_float(s, 0);
      book->delta = s_float(s, 1);
      int count = (int)dim * (int)entries;
      if (book->lookup == 1) count = lookup_count((int)entries, (int)dim);
      if (count > (1 << 20)) return -1;
      uint32_t value_bits = s_int(s, 22, 2, 1, 2, 1, 1, 4) + 1;
      if (value_bits > 16) return -1;
      s_tree(s, 0x2224, 1, 1);
      int center = count / 2;
      book->quant.assign(count, 0);
      for (int j = 0; j < count; j++) {
        int pred = center;
        if (j & 1) pred = count - center - 2;
        uint32_t v = (uint32_t)pred - model_int(&s->models[23], s->r, 4, 1, 4, 0);
        s->w.write(v, value_bits);
        book->quant[j] = (int)v;
        if ((int)v + 1 > book->radix) book->radix = (int)v + 1;
        if (j & 1) center++;
      }
    }
    if (s->r->err) return -1;
    if (build_codes(book) < 0) return -1;
    if (book->lookup) {
      book->context = select_book(s->cache, book, s->probs);
      if (build_lookup(book) < 0) return -1;
    }
  }
  return 0;
}

static int setup_config(SetupDec *s, int channels, std::vector<Codebook> books, VorbisSetup *c) {
  c->books = std::move(books);
  auto count = [&](int slot) { return (int)s_int(s, slot, 3, 1, 2, 0, 1, 6) + 1; };
  int nt = count(24);
  if (nt < 1 || nt > 64) return -1;
  for (int i = 0; i < nt; i++) s->w.write(0, 16);
  int nf = (int)s_int(s, 25, 3, 1, 4, 0, 1, 6) + 1;
  if (nf < 1 || nf > 64) return -1;
  for (int fi = 0; fi < nf; fi++) {
    if (s_tree(s, 0x2226, 1, 16) != 1) return -1;
    FloorCfg f{};
    int np = (int)s_int(s, 26, 3, 1, 4, 0, 1, 5);
    if (np < 0 || np > 31) return -1;
    int maxClass = -1;
    for (int i = 0; i < np; i++) {
      int cl = (int)s_int(s, 27, 2, 1, 2, 0, 1, 4);
      if (cl < 0 || cl > 15) return -1;
      f.partitions.push_back(cl);
      if (cl > maxClass) maxClass = cl;
    }
    for (int i = 0; i < maxClass + 1; i++) {
      FloorClass cl;
      cl.dim = (int)s_tree(s, 0x2228, 3, 3) + 1;
      cl.sub = (int)s_tree(s, 0x2230, 2, 2);
      cl.master = -1;
      if (cl.sub > 0) {
        cl.master = (int)s_int(s, 28, 3, 1, 4, 0, 1, 8);
        if (cl.master < 0 || cl.master >= (int)c->books.size()) return -1;
      }
      for (int j = 0; j < (1 << cl.sub); j++) {
        int book = (int)s_int(s, 29, 3, 1, 4, 1, 1, 8) - 1;
        if (book < -1 || book >= (int)c->books.size()) return -1;
        cl.books.push_back(book);
      }
      f.classes.push_back(cl);
    }
    f.mult = (int)s_tree(s, 0x2234, 2, 2) + 1;
    uint32_t xbits = s_tree(s, 0x2238, 4, 4);
    f.x = {0, 1 << xbits};
    for (int cl : f.partitions) {
      for (int d = 0; d < f.classes[cl].dim; d++) {
        int x = (int)s_int(s, 30, 4, 1, 4, 0, 1, xbits);
        if (x < 0 || x >= (1 << (int)xbits)) return -1;
        for (int prev : f.x)
          if (x == prev) return -1;
        f.x.push_back(x);
      }
    }
    c->floors.push_back(f);
  }
  int nr = count(31);
  if (nr < 1 || nr > 64) return -1;
  for (int ri = 0; ri < nr; ri++) {
    ResidueCfg r{};
    r.kind = (int)s_tree(s, 0x2248, 2, 16);
    r.begin = (int)s_int(s, 32, 4, 1, 4, 0, 1, 24);
    r.end = (int)s_int(s, 33, 4, 1, 4, 0, 1, 24);
    r.size = (int)s_int(s, 34, 4, 1, 1, 1, 1, 24) + 1;
    int nc = (int)s_int(s, 35, 3, 1, 4, 0, 1, 6) + 1;
    s->models[37].value = s->models[29].value;
    s->models[37].delta = 0;
    r.classbook = (int)s_int(s, 37, 3, 1, 4, 1, 2, 8);
    if (r.kind > 2 || r.begin < 0 || r.end < r.begin || r.size < 1 || nc < 1 || nc > 64 || r.classbook < 0 ||
        r.classbook >= (int)c->books.size())
      return -1;
    std::vector<uint32_t> cascade(nc);
    for (int j = 0; j < nc; j++) {
      uint32_t v = model_pred(&s->models[36], model_int(&s->models[36], s->r, 3, 1, 2, 0), 1);
      if (v > 255) return -1;
      cascade[j] = v;
      s->w.write(v & 7, 3);
      if (v > 7) {
        s->w.write(1, 1);
        s->w.write(v >> 3, 5);
      } else {
        s->w.write(0, 1);
      }
    }
    for (uint32_t v : cascade) {
      std::array<int, 8> row = {-1, -1, -1, -1, -1, -1, -1, -1};
      for (int k = 0; k < 8; k++) {
        if ((v >> k) & 1) {
          row[k] = (int)s_int(s, 37, 3, 1, 4, 1, 2, 8);
          if (row[k] < 0 || row[k] >= (int)c->books.size()) return -1;
        }
      }
      r.books.push_back(row);
    }
    c->residues.push_back(r);
  }
  int nm = count(38);
  if (nm < 1 || nm > 64) return -1;
  for (int mi = 0; mi < nm; mi++) {
    s->w.write(0, 16);
    MappingCfg m;
    m.mux.assign(channels, 0);
    int sub = (int)model_pred(&s->models[39], model_int(&s->models[39], s->r, 3, 1, 2, 0), 1);
    if (sub < 0 || sub > 16) return -1;
    if (sub > 0) {
      s->w.write(1, 1);
      s->w.write((uint32_t)(sub - 1), 4);
    } else {
      s->w.write(0, 1);
      sub = 1;
    }
    int ncp = (int)model_pred(&s->models[40], model_int(&s->models[40], s->r, 3, 1, 2, 0), 1);
    if (ncp < 0 || ncp > 256) return -1;
    if (ncp > 0) {
      s->w.write(1, 1);
      s->w.write((uint32_t)(ncp - 1), 8);
    } else {
      s->w.write(0, 1);
    }
    for (int i = 0; i < ncp; i++) {
      uint32_t nb = (uint32_t)bit_len((uint32_t)(channels - 1));
      int mag = (int)s_int(s, 41, 2, 1, 1, 0, 1, nb);
      int angle = (int)s_int(s, 41, 2, 1, 1, 0, 1, nb);
      if (mag < 0 || mag >= channels || angle < 0 || angle >= channels || mag == angle) return -1;
      m.coupling.push_back({mag, angle});
    }
    s->w.write(0, 2);
    if (sub > 1) {
      for (int j = 0; j < channels; j++) {
        m.mux[j] = (int)s_int(s, 42, 2, 1, 2, 0, 1, 4);
        if (m.mux[j] < 0 || m.mux[j] >= sub) return -1;
      }
    }
    for (int i = 0; i < sub; i++) {
      if (s_int(s, 43, 3, 1, 2, 0, 1, 8) != 0) return -1;
      int f = (int)s_int(s, 44, 3, 1, 2, 0, 1, 8);
      int r = (int)s_int(s, 45, 3, 1, 2, 0, 1, 8);
      if (f < 0 || f >= (int)c->floors.size() || r < 0 || r >= (int)c->residues.size()) return -1;
      m.floors.push_back(f);
      m.residues.push_back(r);
    }
    c->mappings.push_back(m);
  }
  int nmode = count(46);
  if (nmode < 1 || nmode > 64) return -1;
  for (int i = 0; i < nmode; i++) {
    ModeCfg m;
    m.large = s_tree(s, 0x224c, 1, 1) != 0;
    s->w.write(0, 32);
    m.mapping = (int)s_int(s, 47, 3, 1, 2, 0, 1, 8);
    if (m.mapping < 0 || m.mapping >= (int)c->mappings.size()) return -1;
    c->modes.push_back(m);
  }
  s->w.write(1, 1);
  return s->r->err ? -1 : 0;
}

struct Audio {
  uint8_t residueHistory[1 << 20];
  uint32_t componentPresent[4], componentSign[4], componentLength[4];
  int lastContext, channels, blocks[2];
  uint32_t modeHistory, prevWindow, nextWindow, floorHistory, granule;
  uint8_t floorLengths[64][256];
  Range *body, *header, *aux;
  Model *models;
  std::vector<uint16_t> *probs;
  VorbisSetup *setup;
  BitW w;
  std::vector<uint8_t> leftover;
};

static uint32_t a_tree(Audio *a, Range *r, int base, int n) {
  int v = 1;
  for (int i = 0; i < n; i++) {
    int idx = base + v;
    if (idx < 0 || idx >= (int)a->probs->size()) {
      r->err = 1;
      return 0;
    }
    v = 2 * v + (int)pbit(r, a->probs, idx);
  }
  return (uint32_t)(v & ((1 << n) - 1));
}

static int a_mode(Audio *a, uint8_t flags, ModeCfg *out) {
  a->w = BitW{};
  a->w.write(0, 1);
  uint32_t ctx = (flags & 1) + 2 * a->modeHistory + 4 * a->nextWindow;
  int n = bit_len((uint32_t)(a->setup->modes.size() - 1));
  uint32_t m = a_tree(a, a->header, (int)(ctx << 6), n);
  if ((int)m >= (int)a->setup->modes.size()) return -1;
  a->w.write(m, (uint32_t)n);
  a->modeHistory = m & 1;
  *out = a->setup->modes[m];
  int block = out->large ? 1 : 0;
  a->granule += (uint32_t)(a->blocks[block] / 2);
  uint32_t prev = 0, next = 0;
  if (out->large) {
    prev = pbit(a->header, a->probs, (int)(0x201 + a->nextWindow));
    next = pbit(a->header, a->probs, (int)(0x205 + a->prevWindow));
    a->w.write(prev, 1);
    a->w.write(next, 1);
  }
  a->prevWindow = prev;
  a->nextWindow = next;
  return a->header->err ? -1 : 0;
}

static int a_floors(Audio *a, const MappingCfg *mapping, std::vector<char> *silent) {
  silent->assign(a->channels, 0);
  for (int ch = 0; ch < a->channels; ch++) {
    int floor = mapping->floors[mapping->mux[ch]];
    FloorCfg &f = a->setup->floors[floor];
    uint32_t present = pbit(a->body, a->probs, (int)(0x2255 + a->floorHistory));
    a->floorHistory = (2 * a->floorHistory + present) & 3;
    a->w.write(present, 1);
    if (present == 0) {
      (*silent)[ch] = 1;
      continue;
    }
    std::vector<int> order(f.x.size());
    for (size_t i = 0; i < order.size(); i++) order[i] = (int)i;
    std::sort(order.begin(), order.end(), [&](int i, int j) { return f.x[i] < f.x[j]; });
    std::vector<int> y(f.x.size());
    int history = 0;
    for (int i : order) {
      uint32_t pr = pbit(a->body, a->probs, 0x225c + history * 128 + floor + i * 4);
      history = (history * 2 + (int)pr) & 3;
      int n = 0;
      if (pr) {
        n = (int)a_tree(a, a->body, 0x1225c + floor * 8 + i * 32 + (int)a->floorLengths[floor][i] * 1024, 3);
        int v = 1, hist = 0;
        for (int j = 0; j < n; j++) {
          int base = 0x2225c + floor * 32 + i * 8192 + n * 132 - 4 + hist - 4 * j;
          int b = (int)pbit(a->body, a->probs, base);
          v = 2 * v + b;
          hist = (2 * hist + b) & 3;
        }
        y[i] = v;
      }
      a->floorLengths[floor][i] = (uint8_t)n;
    }
    static const int kMultN[4] = {256, 128, 86, 64};
    uint32_t nb = (uint32_t)bit_len((uint32_t)(kMultN[f.mult - 1] - 1));
    a->w.write((uint32_t)y[0], nb);
    a->w.write((uint32_t)y[1], nb);
    int pos = 2;
    for (int idx : f.partitions) {
      FloorClass &cl = f.classes[idx];
      std::vector<int> selectors(cl.dim);
      if (cl.sub > 0) {
        int cval = 0;
        for (int j = 0; j < cl.dim; j++) {
          int found = 0;
          for (size_t k = 0; k < cl.books.size(); k++) {
            int book = cl.books[k];
            int entries = 1;
            if (book >= 0) entries = (int)a->setup->books[book].lengths.size();
            if (y[pos + j] < entries) {
              selectors[j] = (int)k;
              found = 1;
              break;
            }
          }
          if (!found) return -1;
          cval |= selectors[j] << (j * cl.sub);
        }
        if (book_write(&a->setup->books[cl.master], &a->w, cval) < 0) return -1;
      }
      for (int j = 0; j < cl.dim; j++) {
        int book = cl.books[selectors[j]];
        if (book >= 0 && book_write(&a->setup->books[book], &a->w, y[pos + j]) < 0) return -1;
      }
      pos += cl.dim;
    }
  }
  return a->body->err ? -1 : 0;
}

static int channel_component(Audio *a, int residue, int context, int pass, int pos, int channel) {
  if (pos < 0 || pos >= 8192) {
    a->body->err = 1;
    return 0;
  }
  if (channel > 3) channel = 3;
  int base = 0x9225c + context * 0x45400;
  int histPos = residue << 18 | (pass > 0 ? pass - 1 : 0) << 15 | pos * 4 | channel;
  uint8_t old = a->residueHistory[histPos];
  int ctx = residue + (pos & ~3) * 8 + channel * 4 + (int)a->componentPresent[0] * 16;
  if ((old & 7) == 0) ctx += 1 << 16;
  if (a->lastContext == context) ctx += 1 << 17;
  uint32_t present = pbit(a->body, a->probs, base + ctx);
  int outPos = residue << 18 | pass << 15 | pos * 4 | channel;
  a->lastContext = context;
  if (present == 0) {
    a->componentPresent[channel] = 0;
    a->componentLength[channel] = 0;
    a->residueHistory[outPos] = 0;
    return 0;
  }
  int zeroCtx = old == 0 ? (1 << 12) : 0;
  int logpos = bit_len((uint32_t)pos);
  ctx = residue + channel * 4 + logpos * 128 + zeroCtx + (int)a->componentPresent[0] * 64 +
        ((int)a->componentSign[channel] + (int)(old & 0x80)) * 16;
  uint32_t sign = pbit(a->body, a->probs, base + 0x40000 + ctx);
  a->componentPresent[channel] = 1;
  a->componentSign[channel] = (2 * a->componentSign[channel] + sign) & 3;
  ctx = residue + channel * 4 + logpos * 256 + zeroCtx + (int)a->componentLength[0] * 32 + (int)sign * 16;
  uint32_t unit = pbit(a->body, a->probs, base + 0x42000 + ctx);
  int v = 1, length = 1;
  if (unit == 0) {
    int n = (int)a_tree(a, a->body, base + 0x44000 + (int)a->componentLength[0] * 128 + residue * 8 + channel * 32, 3);
    v = 1;
    for (int i = 0; i < n + 1; i++) {
      int c = base + 0x44400 + (int)a->componentLength[0] * 64 + residue * 4 + channel * 16 + n * 512 + (v & 3);
      v = 2 * v + (int)pbit(a->body, a->probs, c);
    }
    length = n + 2;
  }
  a->componentLength[channel] = (uint32_t)length;
  a->residueHistory[outPos] = (uint8_t)(length + (int)sign * 128);
  if (sign) v = -v;
  return v;
}

static int a_residues(Audio *a, const MappingCfg *mapping, std::vector<char> *silent) {
  for (auto &pair : mapping->coupling) {
    if (!(*silent)[pair[0]] || !(*silent)[pair[1]]) {
      (*silent)[pair[0]] = 0;
      (*silent)[pair[1]] = 0;
    }
  }
  for (size_t sub = 0; sub < mapping->residues.size(); sub++) {
    int idx = mapping->residues[sub];
    ResidueCfg &r = a->setup->residues[idx];
    if (r.kind != 1 && r.kind != 2) return -1;
    std::vector<int> channels;
    for (int ch = 0; ch < a->channels; ch++)
      if (mapping->mux[ch] == (int)sub && !(*silent)[ch]) channels.push_back(ch);
    if (channels.empty()) continue;
    int interleaved = 0;
    if (r.kind == 2) {
      for (int ch = 0; ch < a->channels; ch++)
        if (mapping->mux[ch] == (int)sub) interleaved++;
      channels.resize(1);
    }
    Codebook *book = &a->setup->books[r.classbook];
    int parts = (r.end - r.begin) / r.size;
    std::vector<std::vector<int>> classes(channels.size(), std::vector<int>(parts + book->dim));
    for (int pass = 0; pass < 8; pass++) {
      for (int part = 0; part < parts; part += book->dim) {
        if (pass == 0) {
          for (size_t ch = 0; ch < channels.size(); ch++) {
            int v = 0;
            for (int j = 0; j < book->dim; j++) {
              int cl = (int)a_tree(a, a->body, 0x6225c + (part + j) * 32 + (idx & 3) * 16, 4);
              if (cl >= (int)r.books.size()) return -1;
              classes[ch][part + j] = cl;
              v = v * (int)r.books.size() + cl;
            }
            if (book_write(book, &a->w, v) < 0) return -1;
          }
        }
        for (int j = 0; j < book->dim && part + j < parts; j++) {
          for (size_t ch = 0; ch < channels.size(); ch++) {
            int bi = r.books[classes[ch][part + j]][pass];
            if (bi < 0) continue;
            Codebook *b = &a->setup->books[bi];
            if (b->lookup == 0) return -1;
            for (int off = 0; off < r.size; off += b->dim) {
              int key = 0;
              int lim = b->dim < r.size - off ? b->dim : r.size - off;
              for (int k = 0; k < lim; k++) {
                int pos = r.begin + (part + j) * r.size + off + k;
                int channel = 0;
                if (interleaved) {
                  channel = pos % interleaved;
                  pos = pos / interleaved;
                }
                int v = channel_component(a, idx & 3, b->context, pass, pos, channel) + b->radix / 2;
                if (v < 0 || v >= b->radix) return -1;
                key = key * b->radix + v;
              }
              auto it = b->symbols.find(key);
              if (it == b->symbols.end()) return -1;
              if (book_write(b, &a->w, it->second) < 0) return -1;
            }
          }
        }
      }
    }
  }
  return a->body->err ? -1 : 0;
}

static int finish_packet(Audio *a, int size) {
  if ((int)a->w.data.size() > size) return -1;
  a->w.n = (uint32_t)a->w.data.size() * 8;
  if ((int)a->w.data.size() < size) {
    uint32_t zero = pbit(a->body, a->probs, 0x214);
    int prev = 0;
    while ((int)a->w.data.size() < size) {
      uint32_t v = 0;
      if (zero == 0) v = a_tree(a, a->body, 0x218 + (prev & 0xf0) * 16, 8);
      a->w.write(v, 8);
      prev = (int)v;
    }
  }
  return a->body->err ? -1 : 0;
}

static int decode_audio_page(Audio *a, const Page *h, std::vector<uint8_t> *body) {
  body->clear();
  for (size_t i = 0; i < h->packets.size(); i++) {
    int size = h->packets[i];
    if (a->leftover.empty()) {
      ModeCfg mode;
      if (a_mode(a, h->flags, &mode) < 0) return -1;
      uint32_t n = model_int(&a->models[7], a->aux, 3, 0, 1, 1);
      if (n != 0) return -1;
      MappingCfg &mapping = a->setup->mappings[mode.mapping];
      std::vector<char> silent;
      if (a_floors(a, &mapping, &silent) < 0) return -1;
      if (a_residues(a, &mapping, &silent) < 0) return -1;
      if ((int)a->w.data.size() <= size) {
        if (finish_packet(a, size) < 0) return -1;
      }
      a->leftover = a->w.data;
    }
    if (size > (int)a->leftover.size()) return -1;
    body->insert(body->end(), a->leftover.begin(), a->leftover.begin() + size);
    a->leftover.erase(a->leftover.begin(), a->leftover.begin() + size);
  }
  return 0;
}

struct CachedHdr {
  std::vector<uint8_t> pages;
  VorbisSetup setup;
  int blocks[2];
  int channels;
};

struct Cursor {
  const uint8_t *p, *end;
};

static int read_size(Cursor *c, uint32_t *out) {
  if (c->p >= c->end) return -1;
  uint8_t b[4] = {};
  b[0] = *c->p++;
  int n = b[0] & 3;
  if (c->p + n > c->end) return -1;
  for (int i = 0; i < n; i++) b[1 + i] = *c->p++;
  *out = ((uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24) >> 2;
  return 0;
}

static int read_frame(Cursor *c, std::vector<uint8_t> *out) {
  uint32_t n;
  if (read_size(c, &n) < 0) return -1;
  if (n > (512u << 20) || c->p + n > c->end) return -1;
  out->assign(c->p, c->p + n);
  c->p += n;
  return 0;
}

static int rewrite_serial(std::vector<uint8_t> *pages, uint32_t serial) {
  int pos = 0;
  int n = (int)pages->size();
  uint8_t *d = pages->data();
  while (pos + 27 <= n) {
    if (d[pos] != 'O' || d[pos + 1] != 'g') return -1;
    int nseg = d[pos + 26];
    int size = 27 + nseg;
    if (size > n - pos) return -1;
    for (int i = 0; i < nseg; i++) size += d[pos + 27 + i];
    if (size > n - pos) return -1;
    d[pos + 14] = (uint8_t)serial;
    d[pos + 15] = (uint8_t)(serial >> 8);
    d[pos + 16] = (uint8_t)(serial >> 16);
    d[pos + 17] = (uint8_t)(serial >> 24);
    memset(d + pos + 22, 0, 4);
    uint32_t crc = ogg_crc(d + pos, size);
    d[pos + 22] = (uint8_t)crc;
    d[pos + 23] = (uint8_t)(crc >> 8);
    d[pos + 24] = (uint8_t)(crc >> 16);
    d[pos + 25] = (uint8_t)(crc >> 24);
    pos += size;
  }
  return 0;
}

static int split_dest(const std::vector<uint8_t> &src, std::vector<uint8_t> *headers, std::vector<uint8_t> *audio) {
  headers->clear();
  audio->clear();
  int pos = 0, n = (int)src.size();
  const uint8_t *d = src.data();
  while (pos + 27 <= n) {
    if (d[pos] != 'O' || d[pos + 1] != 'g') return -1;
    int nseg = d[pos + 26];
    int hsz = 27 + nseg;
    if (hsz > n - pos) return -1;
    int body = 0;
    for (int i = 0; i < nseg; i++) body += d[pos + 27 + i];
    int size = hsz + body;
    if (size > n - pos) return -1;
    uint8_t ptype = body ? d[pos + hsz] : 0;
    if (ptype == 3 || ptype == 5)
      headers->insert(headers->end(), d + pos, d + pos + size);
    else if (ptype != 1)
      audio->insert(audio->end(), d + pos + hsz, d + pos + size);
    pos += size;
  }
  return 0;
}

struct Dec {
  Cursor cur;
  Range cmd;
  uint16_t ctrl[18];
  Model models[55];
  std::vector<uint16_t> probs;
  uint16_t *lace_term;
  uint8_t flags;
  uint32_t previous;
  BookCache cache;
  std::vector<CachedHdr> headers;
  std::vector<std::vector<uint8_t>> streams;
  std::vector<uint8_t> dest, last_stream;
  CachedHdr last_cached;
  uint8_t *dst;
  uint32_t dcap, dpos;
};

static int append_out(Dec *d, const uint8_t *b, size_t n) {
  if (n > d->dcap - d->dpos) return -2;
  if (n) memcpy(d->dst + d->dpos, b, n);
  d->dpos += (uint32_t)n;
  return 0;
}

static int apply_cache(Dec *d, uint32_t serial, std::vector<uint8_t> *pages, VorbisSetup *setup, CachedHdr **ent) {
  if (d->headers.empty()) return -1;
  int back = (int)model_int(&d->models[53], &d->cmd, 5, 0, 2, 1);
  int n = (int)d->headers.size();
#ifdef HOST_DEBUG
  fprintf(stderr, "  cache back=%d of %d m53 nz=%u len=%u cmd_err=%d cmd_pos=%d/%d\n", back, n, d->models[53].nonzero,
          d->models[53].length, d->cmd.err, d->cmd.pos, d->cmd.len);
#endif
  if (back < 0 || back >= n) return -1;
  int index = n - 1 - back;
  CachedHdr &c = d->headers[index];
  d->last_cached = c;
  *pages = c.pages;
  if (rewrite_serial(pages, serial) < 0) return -1;
  *setup = c.setup;
  for (auto &b : setup->books) {
    if (b.lookup) b.context = select_book(&d->cache, &b, &d->probs);
  }
  d->models[37].value = d->models[29].value;
  d->models[37].delta = 0;
  *ent = &d->last_cached;
  return 0;
}

static int dest_copy(Dec *d, Audio *a, Page *first, std::vector<uint8_t> *out, uint32_t serial) {
  std::vector<uint8_t> *src = &d->last_stream;
  if (src->size() < 4 || (*src)[0] != 'O') {
    if (!d->streams.empty())
      src = &d->streams.back();
    else
      src = &d->dest;
  }
  if (src->empty()) return -1;
  if (!first && out->empty()) {
    std::vector<uint8_t> all = *src;
    if (serial && rewrite_serial(&all, serial) < 0) return -1;
    out->insert(out->end(), all.begin(), all.end());
    (void)a;
    return 0;
  }
  std::vector<uint8_t> headers, audio;
  if (split_dest(*src, &headers, &audio) < 0) return -1;
  if (first || !out->empty()) {
    if (rewrite_serial(&headers, serial) < 0) return -1;
    out->insert(out->end(), headers.begin(), headers.end());
  }
  if (audio.empty()) return -1;
  int off = 0;
  auto take = [&](Page *h) -> int {
    int n = 0;
    for (uint8_t v : h->lacing) n += v;
    std::vector<uint8_t> body(n);
    for (int i = 0; i < n; i++) body[i] = audio[(off + i) % (int)audio.size()];
    off += n;
    return marshal_page(out, h, body.data(), n);
  };
  if (first && take(first) < 0) return -1;
  // 03690 extra_copy remaining dest audio pages; do not run further 167c0.
  int pos = 0, n = (int)src->size();
  const uint8_t *p = src->data();
  while (pos + 27 <= n) {
    if (p[pos] != 'O' || p[pos + 1] != 'g') break;
    int nseg = p[pos + 26];
    int hsz = 27 + nseg;
    if (hsz > n - pos) break;
    int body = 0;
    for (int i = 0; i < nseg; i++) body += p[pos + 27 + i];
    int size = hsz + body;
    if (size > n - pos) break;
    uint8_t ptype = body ? p[pos + hsz] : 0;
    if (ptype != 1 && ptype != 3 && ptype != 5) {
      std::vector<uint8_t> page(p + pos, p + pos + size);
      if (rewrite_serial(&page, serial) < 0) return -1;
      out->insert(out->end(), page.begin(), page.end());
    }
    pos += size;
  }
  (void)a;
  return 0;
}

static int decode_audio_pages(Dec *d, Audio *a, std::vector<uint8_t> *out, int page0) {
  for (int page = page0; page < (1 << 20); page++) {
    Page h;
    if (decode_page(a->header, d->models, d->lace_term, 0, a->granule, &h) < 0) {
#ifdef HOST_DEBUG
      fprintf(stderr, "  audio 167c0 fail page=%d hdr_left=%d\n", page, a->header->len - a->header->pos);
#endif
      return -1;
    }
    std::vector<uint8_t> body;
    if (decode_audio_page(a, &h, &body) < 0) {
#ifdef HOST_DEBUG
      fprintf(stderr, "  audio 02790 fail page=%d n=%zu last=%d fl=%02x body_left=%d leftover=%zu\n", page,
              h.packets.size(), h.packets.empty() ? -1 : h.packets.back(), h.flags, a->body->len - a->body->pos,
              a->leftover.size());
#endif
      return -1;
    }
#ifdef HOST_DEBUG
    if (page < page0 + 3 || (h.flags & 4))
      fprintf(stderr, "  audio page=%d n=%zu last=%d fl=%02x body=%zu\n", page, h.packets.size(),
              h.packets.empty() ? -1 : h.packets.back(), h.flags, body.size());
#endif
    if (marshal_page(out, &h, body.data(), (int)body.size()) < 0) return -1;
    if (h.flags & 4) return 0;
  }
  return -1;
}

static int decode_stream(Dec *d, Audio *a, std::vector<uint8_t> *out) {
  Page h;
  if (decode_page(a->header, d->models, d->lace_term, 2, 0, &h) < 0) {
#ifdef HOST_DEBUG
    fprintf(stderr, "  ident 167c0 fail hdr_left=%d err=%d\n", a->header->len - a->header->pos, a->header->err);
#endif
    return -1;
  }
  uint32_t serial = h.serial;
  int ident_like = h.packets.size() == 1 && h.packets[0] <= 32;
  int audio_first = h.packets.size() == 1 && h.packets[0] > 32;
  if (ident_like) {
    SetupDec ident{a->body, d->models, &d->probs, {}, &d->cache};
    ident.w.write(1, 8);
    for (int i = 0; i < 6; i++) ident.w.write((uint8_t)"vorbis"[i], 8);
    ident.w.write(0, 32);
    a->channels = (int)s_int(&ident, 9, 2, 1, 1, 0, 1, 8);
    for (int i = 10; i < 14; i++) s_int(&ident, i, 5, 1, 4, 0, 1, 32);
    uint32_t block = s_int(&ident, 14, 3, 1, 4, 0, 1, 8);
    uint32_t framing = s_int(&ident, 15, 3, 1, 4, 0, 1, 8);
    int small = block & 15, large = (int)(block >> 4);
    if (a->channels < 1 || a->channels > 8 || small < 6 || large > 13 || small > large || (framing & 1) == 0)
      return -1;
    a->blocks[0] = 1 << small;
    a->blocks[1] = 1 << large;
    if (h.packets.size() == 1 && h.packets[0] == (int)ident.w.data.size()) {
      if (marshal_page(out, &h, ident.w.data.data(), (int)ident.w.data.size()) < 0) return -1;
    } else {
      Page ih = h;
      ih.flags = 2;
      ih.sequence = 0;
      ih.packets = {(int)ident.w.data.size()};
      ih.lacing = {(uint8_t)ident.w.data.size()};
      if (marshal_page(out, &ih, ident.w.data.data(), (int)ident.w.data.size()) < 0) return -1;
    }
  }
#ifdef HOST_DEBUG
  fprintf(stderr, "  ident ch=%d ser=%u n=%zu last=%d flags=%02x ident_like=%d audio_first=%d hdr_left=%d\n",
          a->channels, serial, h.packets.size(), h.packets.empty() ? -1 : h.packets.back(), h.flags, ident_like,
          audio_first, a->header->len - a->header->pos);
#endif
  VorbisSetup config;
#ifdef HOST_DEBUG
  int cmd_before_c10 = d->cmd.pos;
#endif
  uint32_t c10 = range_bit(&d->cmd, &d->ctrl[10]);
#ifdef HOST_DEBUG
  fprintf(stderr, "  ctrl10=%u ident_like=%d cmd=%d->%d/%d\n", c10, ident_like, cmd_before_c10, d->cmd.pos, d->cmd.len);
#endif
  if (c10) {
    std::vector<uint8_t> pages;
    CachedHdr *ent = 0;
    if (apply_cache(d, serial, &pages, &config, &ent) < 0) return -1;
    out->insert(out->end(), pages.begin(), pages.end());
    if (ent) {
      a->channels = ent->channels;
      a->blocks[0] = ent->blocks[0];
      a->blocks[1] = ent->blocks[1];
    }
#ifdef HOST_DEBUG
    fprintf(stderr, "  cache headers=%zu\n", d->headers.size());
#endif
    a->setup = &config;
  } else {
    Page hdr;
    // 167c0(a1!=0): n from model 5, laces from dest. n==2 still reads model 6.
    if (decode_page_ex(a->header, d->models, d->lace_term, 0, 0, &hdr, 0) < 0) return -1;
    if (hdr.packets.size() != 2) {
#ifdef HOST_DEBUG
      fprintf(stderr, "  destcopy n=%zu ser=%u fl=%02x hdr_left=%d\n", hdr.packets.size(), hdr.serial, hdr.flags,
              a->header->len - a->header->pos);
#endif
      return dest_copy(d, a, 0, out, serial);
    }
    if (fill_laces(a->header, d->models, d->lace_term, &hdr) < 0) return -1;
    std::vector<uint8_t> comment(hdr.packets[0]);
    int prev = 0;
    for (int i = 0; i < hdr.packets[0]; i++) {
      comment[i] = (uint8_t)a_tree(a, a->body, 0x1218 + (prev & 0xf0) * 16, 8);
      prev = comment[i];
    }
    SetupDec s{a->body, d->models, &d->probs, {}, &d->cache};
    std::vector<Codebook> books;
    if (codebooks(&s, &books) < 0) return -1;
    if (setup_config(&s, a->channels, std::move(books), &config) < 0) return -1;
    a->w = s.w;
    if (finish_packet(a, hdr.packets[1]) < 0) return -1;
    std::vector<uint8_t> body = comment;
    body.insert(body.end(), a->w.data.begin(), a->w.data.end());
    if (marshal_page(out, &hdr, body.data(), (int)body.size()) < 0) return -1;
    CachedHdr stored;
    stored.pages.assign(out->end() - (int)(27 + hdr.lacing.size() + body.size() > (int)out->size() ? 0 : 0),
                        out->end());
    // Store comment+setup pages just appended. Find last two Ogg pages... simpler: copy from after ident.
    stored.setup = config;
    stored.channels = a->channels;
    stored.blocks[0] = a->blocks[0];
    stored.blocks[1] = a->blocks[1];
    // Extract pages after ident from *out. Ident is first page(s).
    {
      int pos = 0, n = (int)out->size();
      const uint8_t *p = out->data();
      // skip ident page(s)
      if (pos + 27 <= n && p[pos] == 'O') {
        int nseg = p[pos + 26];
        int size = 27 + nseg;
        for (int i = 0; i < nseg && pos + 27 + i < n; i++) size += p[pos + 27 + i];
        pos += size;
      }
      stored.pages.assign(out->begin() + pos, out->end());
    }
    d->last_cached = stored;
    if (range_bit(&d->cmd, &d->ctrl[14])) {
      d->headers.push_back(stored);
#ifdef HOST_DEBUG
      fprintf(stderr, "  newhdr store=1 headers=%zu\n", d->headers.size());
#endif
    }
  }
  a->setup = &config;
  return decode_audio_pages(d, a, out, 0);
}

static int next_record(Dec *d) {
#ifdef HOST_DEBUG
  int cmd0 = d->cmd.pos;
#endif
  uint32_t b0 = range_bit(&d->cmd, &d->ctrl[d->previous]);
  if (d->cmd.err) return 1;  // EOF
  d->previous = b0;
  if (b0 == 0) {
    std::vector<uint8_t> raw;
    if (read_frame(&d->cur, &raw) < 0) return d->cur.p >= d->cur.end ? 1 : -1;
    if (raw.empty()) return 1;
    if (append_out(d, raw.data(), raw.size()) < 0) return -2;
    d->dest.insert(d->dest.end(), raw.begin(), raw.end());
    d->last_stream = raw;
#ifdef HOST_DEBUG
    fprintf(stderr, "raw n=%zu total=%u cmd=%d/%d\n", raw.size(), d->dpos, d->cmd.pos, d->cmd.len);
#endif
    return 0;
  }
  if (range_bit(&d->cmd, &d->ctrl[2])) {
    int back = (int)model_int(&d->models[52], &d->cmd, 5, 0, 2, 1);
    int n = (int)d->streams.size();
    if (n == 0) return -1;
    int index = n - 1 - back % n;
    if (index < 0) index += n;
    // RetDec 0x401752: esi+0x6008 is slot 3 (3*0x2000), same integer as 167c0 serial.
    uint32_t serial3 = model_pred(&d->models[3], model_int(&d->models[3], &d->cmd, 5, 2, 4, 0), 1);
    std::vector<uint8_t> rec = d->streams[index];
    if (rewrite_serial(&rec, serial3) < 0) return -1;
    if (append_out(d, rec.data(), rec.size()) < 0) return -2;
    d->dest.insert(d->dest.end(), rec.begin(), rec.end());
    d->last_stream = rec;
#ifdef HOST_DEBUG
    fprintf(stderr, "replay back=%d idx=%d n=%zu ser=%u nz=%u len=%u total=%u cmd=%d/%d\n", back, index, rec.size(),
            serial3, d->models[3].nonzero, d->models[3].length, d->dpos, d->cmd.pos, d->cmd.len);
#endif
    return 0;
  }
  int store = (int)range_bit(&d->cmd, &d->ctrl[6]);
  std::vector<uint8_t> frames[3];
  for (int i = 0; i < 3; i++)
    if (read_frame(&d->cur, &frames[i]) < 0) {
#ifdef HOST_DEBUG
      fprintf(stderr, "  read_frame %d fail leftover=%ld store=%d\n", i, (long)(d->cur.end - d->cur.p), store);
#endif
      return -1;
    }
  static const int kSolid[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23, 27, 28, 29, 30};
  if (d->flags & 8) {
    for (int i : kSolid) {
      d->models[i].value = d->models[i].delta = d->models[i].nonzero = d->models[i].sign = d->models[i].length = 0;
    }
  } else {
    for (int i = 0; i < 52; i++) model_reset(&d->models[i]);
    for (size_t i = 0; i < d->probs.size(); i++) d->probs[i] = 0x8000;
    d->cache.books.clear();
  }
  Range aux, hdr, bod;
  range_init(&aux, frames[0].data(), (int)frames[0].size());
  range_init(&hdr, frames[1].data(), (int)frames[1].size());
  range_init(&bod, frames[2].data(), (int)frames[2].size());
#ifdef HOST_DEBUG
  fprintf(stderr, "  frames aux=%zu hdr=%zu bod=%zu store=%d b0=%u cmd=%d->%d/%d\n", frames[0].size(), frames[1].size(),
          frames[2].size(), store, b0, cmd0, d->cmd.pos, d->cmd.len);
#endif
  for (auto &b : d->cache.books) b.used = 0;
  Audio *audio = new Audio();
  audio->body = &bod;
  audio->header = &hdr;
  audio->aux = &aux;
  audio->models = d->models;
  audio->probs = &d->probs;
  std::vector<uint8_t> rec;
  int st = decode_stream(d, audio, &rec);
  delete audio;
  if (st < 0) {
#ifdef HOST_DEBUG
    fprintf(stderr, "  decode_stream fail recn=%zu\n", rec.size());
#endif
    return -1;
  }
  if (append_out(d, rec.data(), rec.size()) < 0) return -2;
  d->last_stream = rec;
  d->dest.insert(d->dest.end(), rec.begin(), rec.end());
  if (store) d->streams.push_back(rec);
  for (auto &b : d->cache.books)
    if (!b.used && b.uses) b.uses--;
#ifdef HOST_DEBUG
  fprintf(stderr, "rec store=%d n=%zu total=%u\n", store, rec.size(), d->dpos);
#endif
  return 0;
}

static int32_t decode_all(const uint8_t *src, uint32_t slen, uint8_t *dst, uint32_t dcap) {
  if (!src || !dst || slen < 7) return 0;
  if (src[0] != 'O' || src[1] != 'G' || src[2] != 'G' || src[3] != 'R' || src[4] != 'E') return 0;
  if (src[5] != 0) return 0;
  uint8_t flags = src[6];
  if ((flags & 7) > 3) return 0;
  Dec d{};
  d.flags = flags;
  d.dst = dst;
  d.dcap = dcap;
  d.dpos = 0;
  d.cur = {src + 7, src + slen};
  d.previous = 0;
  for (int i = 0; i < 18; i++) d.ctrl[i] = 0x8000;
  for (int i = 0; i < 55; i++) model_reset(&d.models[i]);
  d.cache.capacity = 1 << (4 + (flags & 7));
  d.probs.assign(0x9225c + d.cache.capacity * 0x45400, 0x8000);
  d.lace_term = &d.probs[0x208];
  std::vector<uint8_t> cmdf;
  if (read_frame(&d.cur, &cmdf) < 0) return 0;
  range_init(&d.cmd, cmdf.data(), (int)cmdf.size());
  for (;;) {
    int rc = next_record(&d);
    if (rc > 0) break;
    if (rc == -2) return -2;
    if (rc < 0) {
#ifdef HOST_DEBUG
      fprintf(stderr, "decode err total=%u\n", d.dpos);
      return (int32_t)d.dpos;
#endif
      return 0;
    }
  }
  return (int32_t)d.dpos;
}

}  // namespace

extern "C" int32_t mpzz_decode(uint8_t *src, uint32_t slen, uint8_t *dst, uint32_t dcap) {
  return decode_all(src, slen, dst, dcap);
}

#ifdef HOST_DEBUG
int main(int argc, char **argv) {
  if (argc < 2) return 1;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 1;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  std::vector<uint8_t> src(n);
  if (fread(src.data(), 1, n, f) != (size_t)n) return 1;
  fclose(f);
  uint32_t cap = (uint32_t)n * 4;
  if (cap < (64u << 20)) cap = 64u << 20;
  if (cap > (512u << 20)) cap = 512u << 20;
  std::vector<uint8_t> dst(cap);
  int32_t got = mpzz_decode(src.data(), (uint32_t)n, dst.data(), cap);
  uint32_t crc = 0;
  if (got > 0) {
    static uint32_t ieee[256];
    static int init;
    if (!init) {
      for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1)));
        ieee[i] = c;
      }
      init = 1;
    }
    crc = 0xffffffffu;
    for (int32_t i = 0; i < got; i++) crc = ieee[(crc ^ dst[i]) & 0xff] ^ (crc >> 8);
    crc ^= 0xffffffffu;
    FILE *o = fopen("/tmp/oggre-out.bin", "wb");
    if (o) {
      fwrite(dst.data(), 1, got, o);
      fclose(o);
    }
  }
  fprintf(stderr, "size %d crc %08x head ", got, crc);
  for (int i = 0; i < 32 && i < got; i++) fprintf(stderr, "%02x", dst[i]);
  fprintf(stderr, "\n");
  return got > 0 ? 0 : 2;
}
#endif
