// Package godec — production decode_v22 main loop.
//
// Direct port of garotafitness-fork stream/magic2/guest/main.cpp:976-1581
// (decode_v22) plus the inline helpers it pivots through:
//
//   - decode_opt_header   main.cpp:929-962  (option-header rANS)
//   - decode_opt_int      main.cpp:895-924  (extra-model integer)
//   - decode_mix16_esc    main.cpp:499-512
//   - decode_new_off      main.cpp:516-590
//   - decode_cls11_idx    main.cpp:407-429
//   - fcm_r10             main.cpp:966-974
//   - ctx_lo_pe           main.cpp:862-865
//   - decode_off          main.cpp:742-768
//   - esi_after_match     main.cpp:211-222
//   - extra_sample        main.cpp:705-728
//   - bitlen              main.cpp:642-650
//
// The previous Go port (decode.go:decodeChunkGroup) is a scaffold with
// cls11 + rep-match + literal paths. This file is the production main
// loop that drives BO3 + Silent Hill archives end-to-end:
//
//   1. opt_skip advance + rANS init (PE: 0x14002973b, no renorm)
//   2. use_hdr preamble — decode_opt_header + branch on hdr value
//   3. CDF init block (init_nibble / init_sym8 for every row of every table)
//   4. State init: prev=0, rep0lit=0, rep0=1, esi=0, rolz_reset, reps[32]=1
//   5. FCM extra-class preamble (hdr=3 or 4 with extraA>0)
//   6. Windowed lit preamble (hdr=6 or 8 with extraA>0 && extraB>=4)
//   7. Adaptive decode preamble (hdr=9 with extraA>0)
//   8. Int preamble (hdr=10 or 11 with extraA>0)
//   9. ExtraModel preamble (hdr=12 with extraA>0)
//  10. Raw copy preamble (hdr=7 with extraA>0 && extraB>0)
//  11. Main loop — 1-bit lit/match classifier, 16-sym class decoder,
//      per-class extra + length decoders, MatchCopy fallback for
//      over-bounds rcls distances.
//
// The decoder writes through *State's ROLZ + RingBuffer so cross-chunk
// literals carry into the next chunk's match candidates.
package godec

import (
	"context"
	"io"
)

// =====================================================================
// Non-uniform frequency tables (main.cpp:87-119 + decode_v22 site-specific)
// =====================================================================

// kA697 is the cls10 recent-offset index table (cls10 → offset slot).
// main.cpp:87.
var kA697 = [16]int{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 20, 21}

// kA6A7 is the decode_opt_header first-nibble table (16-sym → option id).
// main.cpp:122.
var kA6A7 = [16]uint8{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x0c, 0x0d, 0x0e, 0x0f, 0x3f, 0x3e, 0x00}

// kA6B7 is the decode_opt_header escape-nibble table (16-sym → option id).
// main.cpp:123.
var kA6B7 = [16]uint8{0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23,
	0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// kNBM is the bmTab size (main.cpp:17, `nBM = 64`).
const kNBM = 64

// kHiStride is the PE-internal stride for wHi/wLo indexing — 0x920 bytes
// per (prev>>bm) row, which decodes to 0x490 uint16s. main.cpp:1054-1055.
const kHiStride = 0x490

// kHiRows is the number of (prev>>bm) rows for wHi/wLo. 16 (4 bits).
const kHiRows = 16

// =====================================================================
// decode_v22 scratch state — the per-call tables that main.cpp:1020-1055
// declares static (so init runs on every call). Putting them in a struct
// lets Reset() seed them once per decode_v22 call without touching the
// per-stream State.
// =====================================================================

type dv22Scratch struct {
	// Literal/Match CDFs. main.cpp:1021-1027.
	hiA     [16][16]uint16
	hiB     [256][16]uint16
	loA     [32][16]uint16
	loB     [256][16]uint16
	clsTab  [4096][16]uint16
	lenTab  [8192][8]uint16
	off8a   [32][8]uint16
	off8b   [32][8]uint16
	off2A   [16]uint16
	off2B   [32][16]uint16
	off2Esc [16]uint16
	off3A   [16]uint16
	off3B   [32][16]uint16
	off3Esc [16]uint16
	off2Mid [32][16]uint16
	off2Tbl [32 * 16][16]uint16 // off2Tail (32 × 16 rows × 16 cols)
	off2Bp  [32 * 16]uint16
	off3Mid [32][16]uint16
	off3Tbl [32 * 16][16]uint16 // off3Tail
	off3Bp  [32 * 16]uint16
	off11A2 [16]uint16
	off11s0 [8]uint16
	off11s1 [8]uint16
	cls10   [16]uint16

	// Mix weights. main.cpp:1042.
	offW2, offW3 uint16

	// Length escape CDFs. main.cpp:1045-1050.
	escA    [256][16]uint16
	escAe   [256][16]uint16
	escB    [2][16]uint16
	escBe   [2][16]uint16
	escW    [256]uint16
	c3A     [16][2][16]uint16
	c3Ae    [16][2][16]uint16
	c3B     [16][16]uint16
	c3W     [16][2]uint16

	// Bit tables + bitmap CDF. main.cpp:1051-1052.
	offBits [4096]uint16
	bmTab   [kNBM]uint16

	// Mix weights for hi/lo path. main.cpp:1055-1056.
	wHi [kHiRows * kHiStride]uint16
	wLo [kHiRows * kHiStride]uint16

	// 1-bit lit/match classifier CDF. main.cpp:1118.
	litP [4096]uint16

	// FCM preamble (hdr=3/4) tables. main.cpp:1132-1133.
	fcmGrid [81 * 16]uint16
	fcmBits [9 * 1024]uint16
}

// reset seeds the scratch CDFs uniformly on every decode_v22 call.
// Mirrors main.cpp:1057-1119 (the static-array init block).
func (s *dv22Scratch) reset() {
	for i := 0; i < 16; i++ {
		init_nibble(s.hiA[i][:])
	}
	for i := 0; i < 256; i++ {
		init_nibble(s.hiB[i][:])
	}
	for i := 0; i < 32; i++ {
		init_nibble(s.loA[i][:])
	}
	for i := 0; i < 256; i++ {
		init_nibble(s.loB[i][:])
	}
	for i := 0; i < 4096; i++ {
		init_nibble(s.clsTab[i][:])
	}
	for i := 0; i < 8192; i++ {
		init_sym8(s.lenTab[i][:])
	}
	for i := 0; i < 32; i++ {
		init_sym8(s.off8a[i][:])
		init_sym8(s.off8b[i][:])
		init_nibble(s.off2B[i][:])
		init_nibble(s.off3B[i][:])
	}
	init_nibble(s.off2A[:])
	init_nibble(s.off2Esc[:])
	init_nibble(s.off3A[:])
	init_nibble(s.off3Esc[:])
	for i := 0; i < 32; i++ {
		init_nibble(s.off2Mid[i][:])
		init_nibble(s.off3Mid[i][:])
	}
	for i := 0; i < 32*16; i++ {
		init_nibble(s.off2Tbl[i][:])
		init_nibble(s.off3Tbl[i][:])
		s.off2Bp[i] = kMB / 2
		s.off3Bp[i] = kMB / 2
	}
	init_nibble(s.off11A2[:])
	init_sym8(s.off11s0[:])
	init_sym8(s.off11s1[:])
	init_nibble(s.cls10[:])
	s.offW2 = 0x8000
	s.offW3 = 0x8000
	for i := 0; i < 256; i++ {
		init_nibble(s.escA[i][:])
		init_nibble(s.escAe[i][:])
		s.escW[i] = 0x8000
	}
	for i := 0; i < 2; i++ {
		init_nibble(s.escB[i][:])
		init_nibble(s.escBe[i][:])
	}
	for i := 0; i < 16; i++ {
		init_nibble(s.c3B[i][:])
		for j := 0; j < 2; j++ {
			init_nibble(s.c3A[i][j][:])
			init_nibble(s.c3Ae[i][j][:])
			s.c3W[i][j] = 0x8000
		}
	}
	for i := 0; i < 4096; i++ {
		s.offBits[i] = kMB / 2
	}
	for i := 0; i < kNBM; i++ {
		s.bmTab[i] = kMB / 2
	}
	for i := 0; i < kHiRows*kHiStride; i++ {
		s.wHi[i] = 0x8000
		s.wLo[i] = 0x8000
	}
	for i := 0; i < 4096; i++ {
		s.litP[i] = kMB / 2
	}
	for i := 0; i < 81; i++ {
		init_nibble(s.fcmGrid[i*16 : (i+1)*16])
	}
	for i := 0; i < 9*1024; i++ {
		s.fcmBits[i] = kMB / 2
	}
}

// =====================================================================
// decode_opt_header (main.cpp:929-962)
// =====================================================================

// dv22Extra is the per-call extraA/extraB + opt-rANS scratch written by
// decode_opt_header and consumed by the use_hdr preambles below.
type dv22Extra struct {
	hdrOpt int
	extraA int
	extraB int
	hdrOff int
	modA   ExtraModel
	modB   ExtraModel
}

// decodeOptHeader mirrors main.cpp:929-962. Reads the option header from
// the rANS state (a 1-bit presence + 16-sym first nibble + 16-sym
// escape + two extra-model integers), and writes gExtraA, gExtraB,
// gHdrOff, gModA, gModB on the caller-supplied dv22Extra.
func decodeOptHeader(r *Rans, e *dv22Extra) int {
	if !r.OK {
		return -1
	}
	var ptab [2]uint16
	ptab[0] = 0x4000
	ptab[1] = 0x4000
	bit := r.GetBit(&ptab[0], 15, 5)
	if bit < 0 {
		return -1
	}
	var row0, row1 [16]uint16
	init_nibble(row0[:])
	init_nibble(row1[:])
	s := r.GetNibble(row0[:], 16, 5, kHdrTgt)
	if s < 0 {
		return -1
	}
	opt := 0
	if s < 15 {
		opt = int(kA6A7[s])
	}
	if s == 15 {
		s2 := r.GetNibble(row1[:], 16, 5, kHdrTgt)
		if s2 < 0 {
			return -1
		}
		opt = int(kA6B7[s2&15])
	}
	e.modA.Init()
	e.modB.Init()
	e.extraA = r.DecodeOptInt(&e.modA, 1)
	e.extraB = r.DecodeOptInt(&e.modB, 1)
	if e.extraA < 0 {
		e.extraA = 0
	}
	if e.extraB < 0 {
		e.extraB = 0
	}
	e.hdrOff = r.Off
	e.hdrOpt = opt
	return opt
}

// =====================================================================
// ctx_lo_pe (main.cpp:862-865)
// =====================================================================

// getNibble9 is the FCM preamble 9-sym variant — same shape as
// GetNibble but with last=9 (rows 9..15 unused in kNibble9Tgt). The
// target table is [9][16]uint16, not the [16][16]uint16 the generic
// adapt16 expects, so we inline adaptation against kNibble9Tgt
// directly.
func getNibble9(r Rans, cdf []uint16) int {
	if !r.OK {
		return -1
	}
	slot := r.X & (kMN - 1)
	quo := r.X >> 15
	i := find16(cdf, slot, 9)
	start := uint32(cdf[i-1])
	var end uint32
	if i < 9 && i < 16 {
		end = uint32(cdf[i])
	} else {
		end = 0x8000
	}
	if end <= start {
		end = start + 1
	}
	r.X = (end-start)*quo + (slot - start)
	sym := i - 1
	if sym < 0 {
		sym = 0
	}
	if sym > 8 {
		sym = 8
	}
	// Adapt toward kNibble9Tgt[sym]. The C++ relies on the 9×16 layout
	// and only ever indexes sym in [0, 8] from the get_nibble caller
	// path — a faithful port matches that by walking 16 slots and
	// pulling each row from kNibble9Tgt (zero-padded for the unused
	// tail).
	for j := 0; j < 16; j++ {
		var t uint16
		if j < 9 {
			t = kNibble9Tgt[sym][j]
		}
		d := int32(t) - int32(cdf[j])
		cdf[j] = uint16(int32(cdf[j]) + (d >> 6))
	}
	r.Renorm()
	return sym
}

func ctxLoPE(prev, hi int) int {
	if hi == ((prev >> 4) & 0xf) {
		return (prev & 0xf) + 16
	}
	return hi
}

// =====================================================================
// decode_cls11_idx (main.cpp:407-429) — per-call variant
// =====================================================================

func (r *Rans) decodeCls11IdxFull(first int, rows []uint16, esc []uint16, bp []uint16) int {
	bl := bitlen(uint32(first))
	if bl < 0 {
		bl = 0
	}
	if bl > 7 {
		bl = 7
	}
	s := r.GetNibble(rows[bl*16:(bl+1)*16], 16, 5, kHdrTgt)
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
	if s > 30 {
		s = 30
	}
	nbits := int(kA6E7[s])
	if nbits > 24 {
		nbits = 24
	}
	d := be0_base(kA6E7[:], s)
	var extra uint32
	for i := 0; i < nbits; i++ {
		b := r.GetBit(&bp[s*16+i], 14, 5)
		if b < 0 {
			return -1
		}
		extra = (extra << 1) | uint32(b)
	}
	return d + int(extra)
}

// =====================================================================
// The main entry point — matches the harness-required signature.
// =====================================================================

// DecodeV22Full is the production decode_v22 main loop. It honours the
// (use_second, use_hdr, opt_skip, force_opt) variant tuple and emits
// the chunk-group output into dst[0:n]. The shape mirrors main.cpp:976.
//
// Returns n>0 on a successful decode (caller checks hit_crc to confirm
// the variant is the right one), n=0 / io.EOF on a no-byte collapse
// (sub-4-byte body, opt_skip past the slice, or rANS underrun before
// the first byte). ctx cancellation surfaces through ctx.Err().
//
// State persistence: *State's ROLZ + RingBuffer carry their learned
// context across calls so chunk N+1's match candidates include chunk
// N's literals. The Rans field is reinitialised from the 4-byte chunk
// header on each call. The dv22Scratch (per-call CDFs, lenTab, etc.)
// is allocated once and reset()ed on every call.
func DecodeV22Full(ctx context.Context, state *State, src []byte, useSecond, useHdr int, optSkip int, forceOpt int, cap uint32) (out []byte, n int, err error) {
	if state == nil {
		return nil, 0, io.EOF
	}
	if optSkip < 0 {
		optSkip = 0
	}
	if optSkip >= len(src) {
		state.LastConsumed = 0
		return nil, 0, io.EOF
	}
	src = src[optSkip:]
	if len(src) < 4 {
		state.LastConsumed = 0
		return nil, 0, io.EOF
	}

	r := Rans{
		Buf: src,
		Off: 4,
		Len: len(src),
		OK:  true,
		X:   uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16 | uint32(src[3])<<24,
	}

	if cap == 0 {
		cap = kWant
	}
	if cap > kWant {
		cap = kWant
	}

	var extra dv22Extra
	hdrOpt := 0
	pre := 0
	if useHdr != 0 {
		opt := decodeOptHeader(&r, &extra)
		if opt < 0 {
			state.LastConsumed = 0
			return nil, 0, io.EOF
		}
		hdrOpt = opt
		if useHdr >= 3 && useHdr != 9 && useHdr != 10 {
			r.X = uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16 | uint32(src[3])<<24
			r.Off = 4
			if (useHdr == 4 || useHdr == 5) && extra.extraB > 0 && extra.extraB+4 <= r.Len {
				r.Off = extra.extraB
				if r.Off+4 <= r.Len {
					r.X = uint32(src[r.Off]) | uint32(src[r.Off+1])<<8 |
						uint32(src[r.Off+2])<<16 | uint32(src[r.Off+3])<<24
					r.Off += 4
				}
			}
		} else if useHdr == 2 && r.Off+4 <= r.Len {
			r.X = uint32(src[r.Off]) | uint32(src[r.Off+1])<<8 |
				uint32(src[r.Off+2])<<16 | uint32(src[r.Off+3])<<24
			r.Off += 4
		}
	}

	var sc dv22Scratch
	sc.reset()

	out = make([]byte, 0, cap)
	prev := 0
	rep0lit := 0
	rep0 := 1
	esi := 0
	if pre > 0 {
		rep0lit = int(out[pre-1])
		prev = rep0lit
	}
	state.ROLZ.Reset()
	var reps [32]int
	for i := range reps {
		reps[i] = 1
	}
	optN := -1
	if forceOpt >= 0 {
		optN = forceOpt
	} else if useHdr != 0 {
		optN = hdrOpt
	} else {
		optN = 0
	}
	if optN < 0 {
		optN = 0
	}
	if optN > 36 {
		optN = 36
	}
	pcMask := int(kPcMask[optN])

	// -----------------------------------------------------------------
	// Preambles — each use_hdr branch seeds extra literals before the
	// main loop. Mirrors main.cpp:1131-1338.
	// -----------------------------------------------------------------

	if (useHdr == 3 || useHdr == 4) && extra.extraA > 0 {
		var fh Hist
		want := extra.extraA
		if want > int(cap) {
			want = int(cap)
		}
		for uint32(len(out)) < cap && r.OK {
			if err := ctx.Err(); err != nil {
				return out, len(out), err
			}
			if r.X < kL && r.Off >= r.Len {
				break
			}
			row := fh.HistRow()
			hn := getNibble9(r, sc.fcmGrid[row*16:(row+1)*16])
			if hn < 0 {
				break
			}
			bsf := hn + 1
			r10 := r.ExtraSample(&fh, sc.fcmBits[:], bsf, fh.HistH1())
			if r10 < 0 {
				break
			}
			b := byte(r10)
			out = append(out, b)
			state.ROLZ.Push(prev, len(out)-1)
			state.ROLZ.Push(int(b), len(out)-1)
			rep0lit = int(b)
			prev = rep0lit
			esi = int(kEsiTab[esi])
			want--
			if want <= 0 {
				break
			}
		}
	}

	if (useHdr == 6 || useHdr == 8) && extra.extraA > 0 && extra.extraB >= 4 {
		var wr Rans
		wr.Buf = src
		wr.Len = extra.extraB
		wr.OK = true
		wr.Off = 4
		wr.X = uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16 | uint32(src[3])<<24
		want := extra.extraA
		if want > int(cap) {
			want = int(cap)
		}
		wn := 0
		wprev := prev
		wesi := esi
		for wn < want && wr.OK {
			ha := (wprev >> 4) & 15
			hb := wprev & 255
			wix := ha*kHiStride + wesi
			if wix < 0 || wix >= kHiRows*kHiStride {
				wix = 0
			}
			hi := wr.GetNibbleMix(sc.hiA[ha][:], sc.hiB[hb][:], &sc.wHi[wix], 16, 6, kMatchTgt)
			if hi < 0 {
				break
			}
			la := ctxLoPE(wprev, hi)
			if la < 0 {
				la = 0
			}
			if la > 31 {
				la = 31
			}
			lo := wr.GetNibbleMix(sc.loA[la][:], sc.loB[hb][:], &sc.wLo[wix], 16, 7, kNibbleTgt)
			if lo < 0 {
				break
			}
			b := byte((hi << 4) | (lo & 15))
			if useHdr == 6 {
				out = append(out, b)
				state.ROLZ.Push(prev, len(out)-1)
				state.ROLZ.Push(int(b), len(out)-1)
				esi = int(kEsiTab[esi])
			}
			wprev = int(b)
			wesi = int(kEsiTab[wesi])
			wn++
		}
		rep0lit = wprev
		prev = rep0lit
		esi = wesi
		if extra.extraB+4 <= len(src) {
			r.Off = extra.extraB
			r.X = uint32(src[r.Off]) | uint32(src[r.Off+1])<<8 |
				uint32(src[r.Off+2])<<16 | uint32(src[r.Off+3])<<24
			r.Off += 4
			r.Len = len(src)
			r.OK = true
		}
	}

	if useHdr == 9 && extra.extraA > 0 {
		M := extra.modA
		want := extra.extraA
		if want > int(cap) {
			want = int(cap)
		}
		for uint32(len(out)) < cap && r.OK {
			if err := ctx.Err(); err != nil {
				return out, len(out), err
			}
			hi := r.GetNibble(M.CDF[0][:], 16, 5, kHdrTgt)
			if hi < 0 {
				break
			}
			lo := r.GetNibble(M.CDF[0][:], 16, 5, kHdrTgt)
			if lo < 0 {
				break
			}
			b := byte((hi << 4) | (lo & 15))
			out = append(out, b)
			state.ROLZ.Push(prev, len(out)-1)
			state.ROLZ.Push(int(b), len(out)-1)
			rep0lit = int(b)
			prev = rep0lit
			esi = int(kEsiTab[esi])
			want--
			if want <= 0 {
				break
			}
		}
		if extra.extraB+4 <= len(src) {
			r.Off = extra.extraB
			r.X = uint32(src[r.Off]) | uint32(src[r.Off+1])<<8 |
				uint32(src[r.Off+2])<<16 | uint32(src[r.Off+3])<<24
			r.Off += 4
			r.Len = len(src)
			r.OK = true
		}
	}

	if (useHdr == 10 || useHdr == 11) && extra.extraA > 0 {
		if useHdr == 11 {
			r.X = uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16 | uint32(src[3])<<24
			r.Off = 4
			if extra.extraB > 0 && extra.extraB <= len(src) {
				r.Len = extra.extraB
			} else {
				r.Len = len(src)
			}
			r.OK = true
		}
		var im IntModel
		im.Init()
		want := extra.extraA
		if want > int(cap) {
			want = int(cap)
		}
		for uint32(len(out)) < cap && r.OK {
			if err := ctx.Err(); err != nil {
				return out, len(out), err
			}
			v := im.DecodePE(&r, prev)
			if v < 0 {
				break
			}
			b := byte(v)
			out = append(out, b)
			state.ROLZ.Push(prev, len(out)-1)
			state.ROLZ.Push(int(b), len(out)-1)
			rep0lit = int(b)
			prev = rep0lit
			esi = int(kEsiTab[esi])
			want--
			if want <= 0 {
				break
			}
		}
		if extra.extraB+4 <= len(src) {
			r.Off = extra.extraB
			r.X = uint32(src[r.Off]) | uint32(src[r.Off+1])<<8 |
				uint32(src[r.Off+2])<<16 | uint32(src[r.Off+3])<<24
			r.Off += 4
			r.Len = len(src)
			r.OK = true
		}
	}

	if useHdr == 12 && extra.extraA > 0 {
		var M ExtraModel
		M.Init()
		want := extra.extraA
		if want > int(cap) {
			want = int(cap)
		}
		for uint32(len(out)) < cap && r.OK {
			if err := ctx.Err(); err != nil {
				return out, len(out), err
			}
			v := r.DecodeOptInt(&M, 1)
			if v < 0 {
				break
			}
			b := byte(v)
			out = append(out, b)
			state.ROLZ.Push(prev, len(out)-1)
			state.ROLZ.Push(int(b), len(out)-1)
			rep0lit = int(b)
			prev = rep0lit
			esi = int(kEsiTab[esi])
			want--
			if want <= 0 {
				break
			}
		}
		r.X = uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16 | uint32(src[3])<<24
		r.Off = 4
		r.Len = len(src)
		r.OK = true
	}

	if useHdr == 7 && extra.extraA > 0 && extra.extraB > 0 {
		want := extra.extraA
		if want > extra.extraB {
			want = extra.extraB
		}
		if want > int(cap) {
			want = int(cap)
		}
		out = append(out, src[:want]...)
		rep0lit = int(out[len(out)-1])
		prev = rep0lit
		for i := 0; i < len(out); i++ {
			esi = int(kEsiTab[esi])
		}
		if extra.extraB+4 <= len(src) {
			r.Off = extra.extraB
			r.X = uint32(src[r.Off]) | uint32(src[r.Off+1])<<8 |
				uint32(src[r.Off+2])<<16 | uint32(src[r.Off+3])<<24
			r.Off += 4
			r.Len = len(src)
			r.OK = true
		}
	}

	// -----------------------------------------------------------------
	// Main loop — 1-bit lit/match classifier, then 16-sym class decoder,
	// then per-class extra + length decoders.
	// -----------------------------------------------------------------

	for uint32(len(out)) < cap && r.OK {
		if err := ctx.Err(); err != nil {
			return out, len(out), err
		}
		if r.X < kL && r.Off >= r.Len {
			break
		}

		n := len(out)
		hist := int(kHistTab[optN][n&pcMask])
		mix := int(kMixTab[hist])
		pctx := hist*32 + esi*2
		if pctx < 0 || pctx+1 >= 4096 {
			break
		}

		bit := r.GetBit(&sc.litP[pctx], 14, 5)
		if bit < 0 {
			break
		}
		tok := bit
		if useSecond != 0 && bit == 0 && mix < 0x63 {
			b2 := r.GetBit(&sc.litP[pctx+1], 14, 5)
			if b2 < 0 {
				break
			}
			if b2 == 1 {
				tok = 2
			}
		}

		if tok == 0 {
			// Literal: hi/lo nibble mix → byte.
			ha := (prev >> 4) & 15
			hb := prev & 255
			wix := ha*kHiStride + esi
			if wix < 0 || wix >= kHiRows*kHiStride {
				wix = 0
			}
			hi := r.GetNibbleMix(sc.hiA[ha][:], sc.hiB[hb][:], &sc.wHi[wix], 16, 6, kMatchTgt)
			if hi < 0 {
				break
			}
			la := ctxLoPE(prev, hi)
			if la < 0 {
				la = 0
			}
			if la > 31 {
				la = 31
			}
			lo := r.GetNibbleMix(sc.loA[la][:], sc.loB[hb][:], &sc.wLo[wix], 16, 7, kNibbleTgt)
			if lo < 0 {
				break
			}
			b := byte((hi << 4) | (lo & 15))
			out = append(out, b)
			state.ROLZ.Push(prev, len(out)-1)
			state.ROLZ.Push(int(b), len(out)-1)
			rep0lit = int(b)
			prev = rep0lit
			esi = int(kEsiTab[esi])
			continue
		}

		if tok == 2 {
			// DXT break — production path emits no DXT bytes, the
			// caller treats it as a chunk-group terminator.
			break
		}

		// Match class decoder.
		crow := esi*16 + hist
		if crow >= 4096 {
			crow = 4095
		}
		cls := r.GetNibble(sc.clsTab[crow][:], 16, 6, kMatchTgt)
		if cls < 0 || cls > 15 {
			break
		}

		extraVal := 0
		mFixed := -1
		switch cls {
		case 1:
			arow := hist % 32
			s0 := r.GetSym8(sc.off8a[arow][:], 6, kOff8Tgt)
			if s0 < 0 {
				break
			}
			var cls1Off int
			if prev >= 10 {
				cls1Off = 8
			} else {
				cls1Off = 0
			}
			brow := (cls1Off + s0) % 32
			s1 := r.GetSym8(sc.off8b[brow][:], 7, kLen8Tgt)
			if s1 < 0 {
				break
			}
			extraVal = s1 + s0*8
			if extraVal < 1 {
				extraVal = 1
			}

		case 2:
			brow := bitlen(uint32(rep0)) % 32
			off2TailRow := func() []uint16 {
				row := make([]uint16, 16)
				copy(row, sc.off2Tbl[brow*16][:])
				return row
			}()
			v := r.DecodeNewOff(sc.off2A[:], sc.off2B[brow][:], &sc.offW2,
				sc.off2Esc[:], sc.off2Bp[:], kA6E7[:], sc.off2Mid[brow][:], off2TailRow)
			if v < 0 {
				break
			}
			extraVal = v

		case 3:
			brow := bitlen(uint32(rep0)) % 32
			off3TailRow := func() []uint16 {
				row := make([]uint16, 16)
				copy(row, sc.off3Tbl[brow*16][:])
				return row
			}()
			v := r.DecodeNewOff(sc.off3A[:], sc.off3B[brow][:], &sc.offW3,
				sc.off3Esc[:], sc.off3Bp[:], kA6E7[:], sc.off3Mid[brow][:], off3TailRow)
			if v < 0 {
				break
			}
			extraVal = v

		case 11:
			ln, idx := 0, 0
			if state.Cls11Mode >= 6 {
				ln = r.DecodeMix16Esc(state.Off11A[:], state.Off11B[0:16], &state.Off11W, state.Off11Esc[:])
				if ln < 0 {
					break
				}
				idx = r.decodeCls11IdxFull(ln, state.Off11B[:], state.Off11Esc[:], state.Off11Bp[:])
				if idx < 0 {
					break
				}
			} else if state.Cls11Mode >= 3 {
				ln = r.DecodeMix16Esc(state.Off11A[:], state.Off11B[0:16], &state.Off11W, state.Off11Esc[:])
				if ln < 0 {
					break
				}
				brow := bitlen(uint32(ln)) % 32
				idx = r.DecodeMix16Esc(state.Off11A2[:], state.Off11B[brow*16:(brow+1)*16], &state.Off11W, state.Off11Esc[:])
				if idx < 0 {
					break
				}
			} else {
				off11MidRow := func() []uint16 {
					row := make([]uint16, 16)
					copy(row, state.Off11Mid[0:16])
					return row
				}()
				off11TailRow := func() []uint16 {
					row := make([]uint16, 16)
					copy(row, state.Off11Tail[0:16])
					return row
				}()
				ln = r.DecodeNewOff(state.Off11A[:], state.Off11B[0:16], &state.Off11W,
					state.Off11Esc[:], state.Off11Bp[:], kA6E7[:],
					off11MidRow, off11TailRow)
				if ln < 0 {
					break
				}
				idx = r.decodeCls11IdxFull(ln, state.Off11B[:], state.Off11Esc[:], state.Off11Bp[:])
				if idx < 0 {
					break
				}
			}
			how := state.Cls11Mode % 3
			switch how {
			case 1:
				extraVal = idx
			case 2:
				extraVal = idx + 1
			default:
				extraVal = state.ROLZ.LookupDistance(prev, idx, n)
			}
			mFixed = ln + 2

		case 10:
			s := r.GetNibble(sc.cls10[:], 16, 6, kMatchTgt)
			if s < 0 {
				break
			}
			extraVal = kA697[s&15]
		}

		dist := DecodeOff(cls, extraVal, &rep0, reps[:], 32)
		m := 0
		if mFixed >= 0 {
			m = mFixed
		} else if cls == 0 {
			m = 1
		} else if cls == 1 || (cls >= 12 && cls <= 15) {
			m = 2
		} else if cls == 2 {
			bl := bitlen(uint32(dist)) & ^3
			var histExtra int
			if hist == 0 {
				histExtra = 2
			} else {
				histExtra = 0
			}
			bctx := (bl + hist*32 + histExtra) % kNBM
			bb := r.GetBit(&sc.bmTab[bctx], 14, 5)
			if bb < 0 {
				break
			}
			m = 3 + bb
		} else if cls == 3 {
			h0 := 0
			if hist == 0 {
				h0 = 1
			}
			bl := bitlen(uint32(dist)) >> 2
			if bl < 0 {
				bl = 0
			}
			if bl > 15 {
				bl = 15
			}
			en := r.DecodeMix16Esc(sc.c3A[bl][h0][:], sc.c3B[bl][:], &sc.c3W[bl][h0], sc.c3Ae[bl][h0][:])
			if en < 0 {
				break
			}
			m = 5 + en
		} else {
			// cls in 4..9 → kA690[cls-4] != 0 flag, else cls==10 / extra != 0
			idxflag := 0
			if cls >= 4 && cls <= 9 {
				if kA690[cls-4] != 0 {
					idxflag = 1
				}
			} else if extraVal != 0 {
				idxflag = 1
			}
			lrow := esi*32 + hist*2 + idxflag
			if lrow >= 8192 {
				lrow = 8191
			}
			ln := r.GetSym8(sc.lenTab[lrow][:], 7, kLen8Tgt)
			if ln < 0 {
				break
			}
			m = ln + 3
			if m == 10 {
				idxflag2 := 0
				if cls >= 4 && cls <= 9 {
					if kA690[cls-4] != 0 {
						idxflag2 = 1
					}
				} else if extraVal != 0 {
					idxflag2 = 1
				}
				arow := ((esi & 127) << 1) | idxflag2
				brow := idxflag2
				en := r.DecodeMix16Esc(sc.escA[arow][:], sc.escB[brow][:], &sc.escW[arow], sc.escAe[arow][:])
				if en < 0 {
					break
				}
				m = 10 + en
			}
		}

		if m <= 0 || dist < 0 {
			break
		}
		for i := 0; i < m && uint32(len(out)) < cap; i++ {
			var b byte
			if dist > 0 && dist <= len(out) {
				b = out[len(out)-dist]
			}
			out = append(out, b)
			state.ROLZ.Push(prev, len(out)-1)
			state.ROLZ.Push(int(b), len(out)-1)
			prev = int(b)
		}
		if len(out) > 0 {
			rep0lit = int(out[len(out)-1])
		}
		esi = EsiAfterMatch(esi, cls, hist)
	}

	state.LastConsumed = r.Off
	state.Esi = uint32(esi)
	state.OptN = uint8(optN)
	state.PcMask = uint8(pcMask)
	state.ExtraA = extra.extraA
	state.ExtraB = extra.extraB
	state.HdrOff = extra.hdrOff
	state.Rans = r

	if len(out) == 0 {
		return nil, 0, io.EOF
	}
	return out, len(out), nil
}

// DecodeV22FullCompat is the harness-required signature wrapper. It
// matches DecodeV22(ctx, st, src, use_second, use_hdr, opt_skip,
// force_opt) by writing into a local scratch buffer. The cap defaults
// to kWant (main.cpp:17).
func DecodeV22FullCompat(ctx context.Context, state *State, src []byte, useSecond, useHdr int, optSkip, forceOpt int) (out []byte, err error) {
	out, _, err = DecodeV22Full(ctx, state, src, useSecond, useHdr, optSkip, forceOpt, kWant)
	return out, err
}