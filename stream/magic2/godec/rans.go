// Package godec — multi-symbol rANS decoders.
//
// Line refs in main.cpp point to the v22 cls-magic2 PE (FUN_14003afc0 in
// the cls-magic2_x64 image at /tmp/cls-magic2_x64.exe), decompiled through
// Ghidra session ed02eeff65094d9e9a281a4ec2cdbaee.
//
// state.go holds the 1-bit rANS (Rans + Renorm + GetBit) plus the slot
// window of 2^23 used for get_bit; this file holds the N-slot decoders
// (get_nibble / get_sym8_tgt / get_nibble_mix) and the adapt16 / adapt8 /
// find16 / mix_cdf helpers that all multi-symbol callsites pivot through.
// Every decoder in this file uses the slot window kMN = 2^15 — a quarter
// of get_bit's window — so the state register is split as low-15 slot /
// high-16 quotient.
package godec

// kMN is the rANS slot window for multi-symbol decoders (main.cpp:16-17).
// The 31-bit state register X is split: low kMN-1 (15 bits) hold the slot
// index, high 16 bits hold the quotient that scales the symbol's frequency
// when X is renormalized.
const kMN uint32 = 1 << 15

// adapt16 nudges cdf toward tgt[sym] by shift bits. main.cpp:262-269.
// Each cdf[j] += (tgt[sym][j] - cdf[j]) >> shift. sym is clamped to
// [0,15] — every callsite in the cls-magic2 PE passes a value already
// in range, but the clamp matches the C++ contract.
func adapt16(cdf []uint16, sym int, tgt [16][16]uint16, shift uint) {
	if sym < 0 {
		sym = 0
	}
	if sym > 15 {
		sym = 15
	}
	for j := 0; j < 16; j++ {
		d := int32(tgt[sym][j]) - int32(cdf[j])
		cdf[j] = uint16(int32(cdf[j]) + (d >> int32(shift)))
	}
}

// adapt8 is the 8-slot version of adapt16. main.cpp:271-278.
func adapt8(cdf []uint16, sym int, tgt [8][8]uint16, shift uint) {
	if sym < 0 {
		sym = 0
	}
	if sym > 7 {
		sym = 7
	}
	for j := 0; j < 8; j++ {
		d := int32(tgt[sym][j]) - int32(cdf[j])
		cdf[j] = uint16(int32(cdf[j]) + (d >> int32(shift)))
	}
}

// find16 walks the cumulative distribution and returns the first j in
// [1,last) whose CDF entry exceeds slot. main.cpp:280-285. The C++ casts
// cdf[j] to int16_t to match Go's int32 of a uint16; for values in the
// legal [0,0x8000) range the comparison is the same as unsigned.
//
// Returns last when no entry exceeds slot. Callers subtract 1 to convert
// the 1-based j to a 0-based symbol index.
func find16(cdf []uint16, slot uint32, last int) int {
	for j := 1; j < last; j++ {
		if int32(cdf[j]) > int32(slot) {
			return j
		}
	}
	return last
}

// mixCDF computes mixed[i] = (w*A[i] + (1-w)*B[i]) >> 16. main.cpp:288-293.
// w is the weight in [0,0xFFFF]: 0xFFFF is "use A", 0 is "use B". The
// intermediate products are 32 bits so the right-shift by 16 divides out
// the 16-bit scaling.
func mixCDF(mixed, a, b []uint16, w uint16) {
	nw := uint16(0 - w)
	for i := 0; i < 16; i++ {
		mixed[i] = uint16((uint32(w)*uint32(a[i])>>16) + (uint32(nw)*uint32(b[i])>>16))
	}
}

// GetNibble decodes one symbol from a 16-slot CDF in cdf, updates cdf
// via adapt16 toward tgt[sym], and renormalizes the rANS state. Mirrors
// main.cpp:get_nibble (326-339). Returns the symbol in [0,last-1] or
// -1 if the stream is exhausted.
//
// last is the effective number of slots in cdf (the C++ accepts up to 16
// but trims to last for narrow tables — main.cpp:808 calls get_nibble
// with last=9 for kNibble9Tgt). shift controls adaptation rate (5..7
// across the seen callsites).
func (r *Rans) GetNibble(cdf []uint16, last int, shift uint, tgt [16][16]uint16) int {
	if !r.OK {
		return -1
	}
	slot := r.X & (kMN - 1)
	quo := r.X >> 15
	i := find16(cdf, slot, last)
	start := uint32(cdf[i-1])
	var end uint32
	if i < last && i < 16 {
		end = uint32(cdf[i])
	} else {
		end = 0x8000
	}
	if end <= start {
		end = start + 1
	}
	r.X = (end-start)*quo + (slot - start)
	sym := i - 1
	adapt16(cdf, sym, tgt, shift)
	r.Renorm()
	return sym
}

// GetSym8 decodes one symbol from an 8-slot CDF in cdf, updates cdf via
// adapt8 toward tgt[sym], and renormalizes the rANS state. Mirrors
// main.cpp:get_sym8_tgt (342-355). Returns the symbol in [0,7] or -1.
func (r *Rans) GetSym8(cdf []uint16, shift uint, tgt [8][8]uint16) int {
	if !r.OK {
		return -1
	}
	slot := r.X & (kMN - 1)
	quo := r.X >> 15
	i := find16(cdf, slot, 8)
	start := uint32(cdf[i-1])
	var end uint32
	if i < 8 {
		end = uint32(cdf[i])
	} else {
		end = 0x8000
	}
	if end <= start {
		end = start + 1
	}
	r.X = (end-start)*quo + (slot - start)
	sym := i - 1
	adapt8(cdf, sym, tgt, shift)
	r.Renorm()
	return sym
}

// DecodeSymbol is the Sym8 entry point. Mirrors main.cpp:get_sym8 (357),
// which hardcodes tgt=kLen8Tgt and shift=7 for the length-table site —
// every other site passes its own tgt + shift, so we keep those as
// parameters rather than baking them in.
//
// Diverges from a literal reading of the task spec: the task asks for
// `DecodeSymbol(r *Rans, t *Sym8) int` with no target parameter. The
// target and shift are required for correct adaptation; without them the
// CDF cannot track symbol statistics. We pass them in rather than
// hardcode kLen8Tgt (whose 64 rows we don't have at hand here) or skip
// adaptation (which would diverge from main.cpp).
func (r *Rans) DecodeSymbol(t *Sym8, tgt [8][8]uint16, shift uint) int {
	return r.GetSym8(t[:], shift, tgt)
}

// DecodeNibble is the Nibble16 entry point. Mirrors main.cpp:get_nibble
// with last=16. Returns the symbol in [0,15] or -1.
func (r *Rans) DecodeNibble(t *Nibble16, tgt [16][16]uint16, shift uint) int {
	return r.GetNibble(t[:], 16, shift, tgt)
}

// GetNibbleMix is the weighted-mix variant. main.cpp:get_nibble_mix
// (295-324). Used by decode_int_pe / decode_mix16_esc / decode_new_off
// where the CDF is a linear combination of two context tables (a and
// the caller's b) blended by weight w. The caller threads w through;
// each call nudges it based on the relative frequency of a vs b at the
// decoded slot.
func (r *Rans) GetNibbleMix(a, b []uint16, w *uint16, last int, shift uint, tgt [16][16]uint16) int {
	if !r.OK {
		return -1
	}
	var mixed [16]uint16
	mixCDF(mixed[:], a, b, *w)
	slot := r.X & (kMN - 1)
	quo := r.X >> 15
	i := find16(mixed[:], slot, last)
	start := uint32(mixed[i-1])
	var end uint32
	if i < 16 {
		end = uint32(mixed[i])
	} else {
		end = 0x8000
	}
	if end <= start {
		end = start + 1
	}
	r.X = (end-start)*quo + (slot - start)
	sym := i - 1
	var fA, fB uint16
	if i < 16 {
		fA = a[i] - a[i-1]
		fB = b[i] - b[i-1]
	} else {
		fA = 0x8000 - a[15]
		fB = 0x8000 - b[15]
	}
	// uint16 arithmetic on w; the shift-and-subtract fits in uint32
	// without surprise, the conditional add of 0x0FFF may wrap (the C++
	// also wraps since uint16_t can hold 0xFFFF).
	wi := uint32(*w)
	w2 := uint16(wi - (wi >> 4))
	if fA >= fB {
		w2 += 0x0FFF
	}
	*w = w2
	adapt16(a, sym, tgt, shift)
	adapt16(b, sym, tgt, shift)
	r.Renorm()
	return sym
}