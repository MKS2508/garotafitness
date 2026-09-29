// Package godec — bitplane-encoded integer decoder (IntModel).
//
// Direct port of garotafitness-fork stream/magic2/guest/main.cpp:431-492
// (struct IntModel + decode_int_pe). The integer decoder is the v22
// "match offset" path — the 16-bit classify flag selects between literal
// (class 0) and IntModel (everything else), and IntModel produces the
// actual offset that the match branch consumes.
//
// The C++ struct carries six adaptive state arrays:
//
//	A       the primary 16-slot CDF (init_nibble)
//	Brow[bl] 16 sub-CDFs selected by bitlen(lookback); bl in [0,15]
//	w       the mix weight for get_nibble_mix(A, Brow[bl], w)
//	s2[16]  16 sub-CDFs picked by srow (s clamped to [0,15])
//	s3[16]  16 sub-CDFs picked by s2 (the second-stage symbol)
//	bp[16]  16 single-bit CDFs used by get_bit for the extra bits
//
// All four 16×16 arrays are seeded uniformly via init_nibble on every
// row; bp is seeded at kMB/2 (the equiprobable midpoint).
package godec

// kMB is the rANS slot window for the 1-bit get_bit decoder used by
// the IntModel extra-bits path. main.cpp:16 (uint32_t kMB = 1u << 14).
const kMB uint16 = 1 << 14

// kA6E7 is the {nbits8} per-symbol table for the IntModel escape +
// bitplane path. main.cpp:362-365. 31 entries; index 15 (= 15+escape)
// stretches the table from the 16-row uniform CDF out to 31 distinct
// nbits values. decode_int_pe clamps s to [0,30] before reading.
var kA6E7 = [31]uint8{
	5, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
	5, 6, 7, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
}

// IntModel is the bitplane-encoded integer decoder's adaptive state.
// Mirrors main.cpp:432-439 (struct IntModel). The C++ allocates this
// inline in a 0x42-byte window of the per-stream allocation; here it
// is a standalone value the caller threads through DecodePE.
//
// Init seeds every CDF uniformly (main.cpp:441-450). DecodePE advances
// the CDFs as it consumes bits — see main.cpp:452-492.
type IntModel struct {
	A     [16]uint16      // primary 16-slot CDF
	Brow  [16][16]uint16  // per-lookback sub-CDFs
	w     uint16          // mix weight for get_nibble_mix
	s2    [16][16]uint16  // second-stage sub-CDFs (selected by srow)
	s3    [16][16]uint16  // third-stage sub-CDFs (selected by s2)
	bp    [16]uint16      // 16 single-bit CDFs for the extra bits
}

// Init seeds every CDF in m uniformly and resets w to its midpoint.
// Mirrors main.cpp:441-450 (int_model_init).
func (m *IntModel) Init() {
	init_nibble(m.A[:])
	for i := 0; i < 16; i++ {
		init_nibble(m.Brow[i][:])
		init_nibble(m.s2[i][:])
		init_nibble(m.s3[i][:])
		m.bp[i] = kMB / 2
	}
	m.w = 0x8000
}

// bitlen returns the position of the highest set bit in x (0 for x==0).
// Mirrors main.cpp:642-650. Used to select the Brow sub-CDF based on
// the magnitude of the previous offset (lookback).
func bitlen(x uint32) int {
	if x == 0 {
		return 0
	}
	n := 0
	for x != 0 {
		x >>= 1
		n++
	}
	return n
}

// be0_base returns the sum of 1<<nb[i] for i in [0,s). Mirrors
// main.cpp:374-383. Used to compute the cumulative base of the
// bitplane-decoded integer — be0_base(kA6E7, _, s) + extra bits = the
// decoded value's lower bound, before the higher-order refinement adds
// s2/s3/raw/b.
//
// nb[i] >= 30 short-circuits the loop because 1<<30 already covers the
// entire 32-bit range — adding more terms would overflow.
func be0_base(nb []uint8, s int) int {
	if s > len(nb) {
		s = len(nb)
	}
	b := 0
	for i := 0; i < s; i++ {
		n := int(nb[i])
		if n >= 30 {
			break
		}
		b += 1 << uint(n)
	}
	return b
}

// DecodePE decodes one bitplane-encoded integer. Mirrors main.cpp:452-492
// (decode_int_pe). Returns -1 if the rANS stream is exhausted at any
// point.
//
// The shape of the call:
//
//	s = mix16(A, Brow[bitlen(lookback)])   (with kHdrTgt, shift=5)
//	if s == 15: s = 15 + nibble(A, kHdrTgt)   (escape)
//	clamp s to [0,30]
//	nbits = kA6E7[s], base = be0_base(kA6E7, s)
//	if nbits < 6: read nbits bits via bp[s&15] and return base+extra
//	else:
//	  srow = s if s<=15 else 15
//	  s2 = nibble(s2[srow], kMatchTgt, shift=6)
//	  sh = (nbits >= 9) ? ((nbits+60) & 63) : 5
//	  raw = (nbits > 9) ? low-(nbits+23)&31 bits, shifted left by 5 : 0
//	  s3 = nibble(s3[s2&15], kNibbleTgt, shift=7)
//	  b  = get_bit(bp[srow], 14, 5)
//	  return base + (s2<<sh) + raw + 2*s3 + b
//
// lookback is the previous decoded offset; it selects which Brow row to
// blend A against and lets the adaptive CDF exploit correlation between
// consecutive offsets.
func (m *IntModel) DecodePE(r *Rans, lookback int) int {
	if !r.OK {
		return -1
	}

	bl := bitlen(uint32(lookback))
	if bl > 15 {
		bl = 15
	}

	// Stage 1: mix16 A vs Brow[bl] with kHdrTgt, shift=5.
	s := r.GetNibbleMix(m.A[:], m.Brow[bl][:], &m.w, 16, 5, kHdrTgt)
	if s < 0 {
		return -1
	}

	// Escape: s == 15 stretches the symbol range to 15..30 via a
	// second nibble from A alone (no mix — only the primary CDF
	// tracks the high-tail distribution).
	if s == 15 {
		e := r.GetNibble(m.A[:], 16, 5, kHdrTgt)
		if e < 0 {
			return -1
		}
		s = 15 + e
	}
	if s < 0 {
		s = 0
	}
	if s > 30 {
		s = 30
	}

	nbits := int(kA6E7[s])
	base := be0_base(kA6E7[:], s)

	// Short path: read nbits bits via bp[s&15] and return.
	if nbits < 6 {
		extra := 0
		for i := 0; i < nbits; i++ {
			b := r.GetBit(&m.bp[s&15], 14, 4)
			if b < 0 {
				return -1
			}
			extra = extra*2 + b
		}
		return base + extra
	}

	// Long path: three nibbles + raw bitplane prefix + one bit.
	srow := s
	if srow > 15 {
		srow = 15
	}

	s2 := r.GetNibble(m.s2[srow][:], 16, 6, kMatchTgt)
	if s2 < 0 {
		return -1
	}

	sh := 5
	if nbits >= 9 {
		sh = (nbits + 60) & 63
	}

	raw := 0
	if nbits > 9 {
		rb := (nbits + 23) & 31
		mask := uint32(1)<<uint(rb) - 1
		raw = int(r.X & mask)
		r.X >>= uint(rb)
		r.Renorm()
		raw <<= 5
	}

	s3 := r.GetNibble(m.s3[s2&15][:], 16, 7, kNibbleTgt)
	if s3 < 0 {
		return -1
	}

	b := r.GetBit(&m.bp[srow], 14, 5)
	if b < 0 {
		return -1
	}

	return base + (s2 << sh) + raw + 2*s3 + b
}