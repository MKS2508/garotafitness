// Package godec — Histogram + ExtraModel + recent-offset helpers.
//
// Hist is the cls-magic2 boundary-detection state (already declared in
// tables.go to keep the field layout with the rest of the per-stream
// struct mirrors). This file ports the methods that operate on it plus
// the option-header ExtraModel and the recent-offset helpers
// (decode_off / insert_new_off / esi_after_match) that the LZ loop
// pivots through. All methods are direct ports of
// garotafitness-fork stream/magic2/guest/main.cpp:
//
//	hist_h1       main.cpp:676-678
//	hist_row      main.cpp:680-688
//	apply_sample  main.cpp:690-703
//	extra_sample  main.cpp:705-730
//	insert_new_off main.cpp:732-739
//	decode_off    main.cpp:742-768
//	extra_init    main.cpp:884-892
//	decode_mix16_esc main.cpp:499-514
//	decode_new_off   main.cpp:516-590
//	esi_after_match  main.cpp:211-224
package godec

// kExtraBits is the per-ExtraModel bits[] capacity. main.cpp:877
// (`static const int kExtraBits = 2048`). The struct field is sized
// to this constant; the bits array the caller passes to ExtraSample is
// sized larger (9*2048/2 = 9216 entries, see kEsiTab-style stride in
// decode_iir / decode_v22) so the computed bit-offset never overflows
// under valid (h1, sym) inputs.
const kExtraBits = 2048

// ExtraModel is the option-header integer decoder's adaptive state.
// Mirrors main.cpp:876-882 (struct ExtraModel). The PE keeps it
// alongside gModA/gModB at module scope; here it is a standalone value
// the caller threads through Init + DecodeOptInt (the latter is
// wired in a separate port — see models_test.go for the init
// contract).
//
//	Ctx8   last-bit context for the presence-bit stream
//	CtxA   last-symbol context for the symbol stream
//	P0     16 single-bit CDFs for the presence bit, one per ctx8 state
//	CDF    16 × 16 CDFs for the symbol stream, indexed by CtxA
//	Esc    16 × 16 CDFs for the 15-escape tail (kHdrTgt)
//	Bits   kExtraBits single-bit CDFs for the bitplane tail
//
// Init seeds every CDF uniformly and resets the contexts. main.cpp:884-892.
type ExtraModel struct {
	Ctx8 uint8
	CtxA uint8
	P0   [16]uint16
	CDF  [16][16]uint16
	Esc  [16][16]uint16
	Bits [kExtraBits]uint16
}

// Init seeds every CDF in m uniformly and resets the contexts. Mirrors
// main.cpp:884-892 (extra_init). The P0/Bits single-bit CDFs seed at
// 0x4000 (the equiprobable midpoint of the 14-bit slot window kMB);
// CDF/Esc use init_nibble to seed the 16-slot uniform distribution.
func (m *ExtraModel) Init() {
	m.Ctx8 = 0
	m.CtxA = 0
	for i := 0; i < 16; i++ {
		m.P0[i] = 0x4000
		init_nibble(m.CDF[i][:])
		init_nibble(m.Esc[i][:])
	}
	for i := range m.Bits {
		m.Bits[i] = 0x4000
	}
}

// HistH1 returns bitlen(|W20 - W24|) cast to uint8, the per-call
// narrowness used to select the extra-sample bit plane. main.cpp:676-678.
func (h *Hist) HistH1() int {
	d := abs32(int32(h.W20) - int32(h.W24)) & 0xff
	return bitlen(d)
}

// HistRow returns the 81-entry row index `h0*9 + h1` clamped to
// [0, 80] where h0 = bitlen((|W08-W0C| + |W10-W14|) >> 1) and
// h1 = HistH1(). main.cpp:680-688.
func (h *Hist) HistRow() int {
	a := abs32(int32(h.W08) - int32(h.W0C))
	b := abs32(int32(h.W10) - int32(h.W14))
	avg := ((a + b) >> 1) & 0xff
	h0 := bitlen(avg)
	h1 := h.HistH1()
	r := h0*9 + h1
	if r < 0 {
		return 0
	}
	if r >= 81 {
		return 80
	}
	return r
}

// ApplySample shifts the 8-slot histogram left by 2 and writes
// (|n0| OR 1) + 2*W20) >> 1) & 0xff into W18/W20, similarly for n1→W1C/W24.
// main.cpp:690-703. The `| 1` keeps the running sum from collapsing to
// 0 (which would freeze the histogram); the `& 0xff` truncates to the
// 8-bit field the PE observes.
func (h *Hist) ApplySample(n0, n1 uint32) {
	a0 := abs32(int32(n0)) | 1
	a1 := abs32(int32(n1)) | 1
	m0 := ((a0 + 2*h.W20) >> 1) & 0xff
	m1 := ((a1 + 2*h.W24) >> 1) & 0xff
	h.W08 = h.W10
	h.W0C = h.W14
	h.W10 = h.W20
	h.W14 = h.W24
	h.W18 = m0
	h.W1C = m1
	h.W20 = m0
	h.W24 = m1
}

// ExtraSample decodes a histogram sample. bsf is the 9-sym magnitude
// (caller typically sets bsf = nibble(grid) + 1, where nibble is the
// 9-symbol hi-row decode). h1 is the precomputed HistH1 (caller
// passes it so the function does not recompute it on the hot path).
//
// Mirrors main.cpp:705-730 (extra_sample). Returns the sample value
// (in [0, 8)) and mutates h via ApplySample. Returns -1 if the rANS
// stream is exhausted.
//
// The bit-offset arithmetic (h1<<11) + ((sym-1)<<8) + i*32 + 8*rdx) / 2
// produces values that can exceed len(bits) for the maximum input
// envelope (h1=8, sym=8, i=7, rdx=3 → off/2 = 9212). All cls-magic2
// callers pass a bits slice sized at 9*2048/2 = 9216 entries
// (decode_iir's hiBits at main.cpp:787; the cls-v22 hiBits/offBits
// arrays in decode_v22 at line 1059), so the maximum off fits. The
// function does NOT bounds-check; the caller must size bits
// accordingly.
func (r *Rans) ExtraSample(h *Hist, bits []uint16, bsf, h1 int) int {
	if bsf <= 1 {
		h.ApplySample(0, 0)
		return 0
	}
	sym := bsf - 1
	if sym > 8 {
		sym = 8
	}
	if h1 < 0 {
		h1 = 0
	}
	if h1 > 8 {
		h1 = 8
	}
	var r10, r13, rdx int
	for i := 0; i < sym; i++ {
		off := (h1 << 11) + ((sym - 1) << 8) + i*32 + 8*rdx
		off /= 2
		b0 := r.GetBit(&bits[off], 14, 4)
		if b0 < 0 {
			return -1
		}
		b1 := r.GetBit(&bits[off+1+b0], 14, 4)
		if b1 < 0 {
			return -1
		}
		r10 = r10*2 + b0
		r13 = r13*2 + b1
		rdx = b1 + 2*b0
	}
	h.ApplySample(uint32(r10), uint32(r13))
	return r10
}

// DecodeMix16Esc is the mix16 + 15-escape decoder used by the length
// tables (off2A/off3A/off11A paths in decode_v22). Mirrors
// main.cpp:499-514. Returns the decoded symbol in [0, 30] or -1 on
// rANS underrun. The 15-escape path extends the symbol range to
// 15..30 by reading a second nibble from the plain (non-mixed) esc
// table.
func (r *Rans) DecodeMix16Esc(a, b []uint16, wp *uint16, esc []uint16) int {
	s := r.GetNibbleMix(a, b, wp, 16, 5, kHdrTgt)
	if s < 0 {
		return -1
	}
	if s == 15 {
		sx := r.GetNibble(esc, 16, 5, kHdrTgt)
		if sx < 0 {
			return -1
		}
		s = 15 + sx
	}
	return s
}

// DecodeNewOff is the 16-sym escape + kA6E7 bitplane decoder used by
// cls2/cls3/cls11 for the recent-offset table. Mirrors main.cpp:516-590
// (decode_new_off). Returns the decoded offset (non-negative) or -1
// on rANS underrun.
//
// The shape:
//
//	s = mix16(a, b, kb hdr_tgt, shift=5)
//	if s == 15: s = 15 + nibble(esc, kHdrTgt)
//	clamp s to [0, 30]
//	nbits = nbtab[s], base = be0_base(nbtab, s)
//	if nbits <= 5: read nbits bits via bp[s*16..], return base+extra
//	else:
//	  s2 = nibble(mid[s*16:], kMatchTgt, shift=6)
//	  sh = ((nbits<9 ? 9 : nbits) + 60) & 63
//	  if nbits > 9: read (nbits-9) raw bits and shift left by 5
//	  s3 = nibble(tail[(s*16+s2)*16:], kNibbleTgt, shift=7)
//	  bit = get_bit(bp[s*16+s2], 14, 5)
//	  return base + (s2<<sh) + raw + 2*s3 + bit
//
// Caller sizes mid as a [s*16+16] slice, tail as [(s*16+s2+1)*16], and
// bp as [(s+1)*16] (or larger). The function does NOT bounds-check.
func (r *Rans) DecodeNewOff(a, b []uint16, wp *uint16, esc, bp []uint16, nbtab []uint8, mid, tail []uint16) int {
	s := r.GetNibbleMix(a, b, wp, 16, 5, kHdrTgt)
	if s < 0 {
		return -1
	}
	if s == 15 {
		sx := r.GetNibble(esc, 16, 5, kHdrTgt)
		if sx < 0 {
			return -1
		}
		s = 15 + sx
	}
	if s < 0 {
		s = 0
	}
	if s >= len(nbtab) {
		s = len(nbtab) - 1
	}
	if s > 30 {
		s = 30
	}
	nbits := int(nbtab[s])
	if nbits > 24 {
		nbits = 24
	}
	d := be0_base(nbtab, s)
	if nbits <= 5 {
		var extra uint32
		for i := 0; i < nbits; i++ {
			bit := r.GetBit(&bp[s*16+i], 14, 5)
			if bit < 0 {
				return -1
			}
			extra = (extra << 1) | uint32(bit)
		}
		return d + int(extra)
	}
	s2 := r.GetNibble(mid[s*16:], 16, 6, kMatchTgt)
	if s2 < 0 {
		return -1
	}
	sh := ((func() int {
		if nbits < 9 {
			return 9
		}
		return nbits
	}()) + 60) & 63
	d += s2 << sh
	if nbits > 9 {
		k := nbits - 9
		low := r.X & ((1 << uint(k)) - 1)
		r.X >>= uint(k)
		r.Renorm()
		d += int(low << 5)
	}
	s3 := r.GetNibble(tail[(s*16+s2)*16:], 16, 7, kNibbleTgt)
	if s3 < 0 {
		return -1
	}
	bit := r.GetBit(&bp[s*16+s2], 14, 5)
	if bit < 0 {
		return -1
	}
	return d + 2*s3 + bit
}

// DecodeOff selects the recent-offset slot for a match class and
// rotates reps[] so the selected slot becomes the new [0]. Returns
// the new distance. Mirrors main.cpp:742-768 (decode_off).
//
// The class-dispatch:
//
//	cls == 0:  return *rep0 (bumps to 1 if it was 0)
//	cls in [4..9]: idx = kA690[cls-4]; rotate + return reps[idx]
//	cls == 10: idx = extra; rotate + return reps[idx]
//	cls in [12..15]: idx = cls-12; rotate + return reps[idx]
//	otherwise (cls in {1,2,3,11}): insert `extra` at reps[17]
//
// `extra` is the integer the caller just decoded (DecodeNewOff for
// cls1/2/3/11, the result of cls4..10/12..15 self-decoding into the
// slot, or the precomputed cls0 distance).
//
// `rep0` mirrors the PE's separate `*rep0` slot for class 0 — every
// call writes through it so the next cls0 read sees the most recent
// distance even if reps[] is short or stale.
func DecodeOff(cls, extra int, rep0 *int, reps []int, nrep int) int {
	if cls == 0 {
		if *rep0 < 1 {
			*rep0 = 1
		}
		return *rep0
	}
	if (cls >= 4 && cls <= 10) || (cls >= 12 && cls <= 15) {
		idx := extra
		if cls >= 12 {
			idx = cls - 12
		} else if cls != 10 {
			idx = kA690[cls-4]
		}
		if idx >= 0 && idx < nrep {
			d := reps[idx]
			if idx > 0 {
				for i := idx; i > 0; i-- {
					reps[i] = reps[i-1]
				}
			}
			if d < 1 {
				d = 1
			}
			reps[0] = d
			*rep0 = d
			return d
		}
	}
	d := extra
	if d < 0 {
		d = 0
	}
	InsertNewOff(reps, nrep, d)
	return d
}

// InsertNewOff pushes d into reps[17] with a 3-step cascade. Mirrors
// main.cpp:732-739. The cls-magic2 PE keeps reps[18..20] as a small
// ring buffer for cls1/cls2/cls3 offsets; on a fresh insert of a new
// distance, the tail shifts up and reps[17] absorbs the new value.
//
// `nrep` is the size of the reps slice (caller passes the LZ-loop's
// working-set length, typically 32 for cls11 / 4 for cls1). Slots
// beyond nrep are untouched. If nrep <= 17 the function is a no-op.
func InsertNewOff(reps []int, nrep int, d int) {
	if nrep > 20 {
		reps[20] = reps[19]
	}
	if nrep > 19 {
		reps[19] = reps[18]
	}
	if nrep > 18 {
		reps[18] = reps[17]
	}
	if nrep > 17 {
		reps[17] = d
	}
}

// EsiAfterMatch returns the next ESI index for a match class. The
// lookup uses hist (the local 16-row sub-histogram selector) rather
// than the live esi register, because match classes index the ESI
// transition table by sub-histogram identity. main.cpp:211-224.
//
//	cls == 0:                       row 48 (cls0 sub-histogram)
//	cls in [4..10] ∪ [12..15]:      row 32 (long-match sub-histogram)
//	cls in {1,2,3,11}:              row 16 (short-match sub-histogram)
//
// The `esi` parameter is unused (it indexes kEsiTab only on the
// literal path; the match path uses hist). It is kept in the
// signature to mirror main.cpp exactly so the cls-magic2 call sites
// compile unchanged.
func EsiAfterMatch(esi, cls, hist int) int {
	_ = esi
	var i int
	switch {
	case cls == 0:
		i = 48 + (hist & 15)
	case (cls >= 4 && cls <= 10) || (cls >= 12 && cls <= 15):
		i = 32 + (hist & 15)
	default:
		i = 16 + (hist & 15)
	}
	if i < 0 {
		i = 0
	}
	if i >= 336 {
		i = 335
	}
	return int(kEsiTab[i])
}