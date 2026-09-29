package godec

import "testing"

// TestGetSym8UniformSlotMid is the primary hand-computed test the task
// asks for. Setup:
//
//	X = 0x8000C321 → X >> 15 = 0x10001 (quotient) — bit 31 set, bit 15
//	                  set, so the shifted result is 1000...0001.
//	                  X & 0x7FFF = 0x4321 (slot)
//	Uniform CDF: [0x0000,0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000]
//
// find16 walks looking for the first cdf[j] > slot=0x4321. 0x1000, 0x2000,
// 0x3000, 0x4000 are all <= 0x4321; 0x5000 > 0x4321, return j=5. So sym=4.
//
// State update: r.X = (end-start)*quo + (slot-start)
//               = (0x5000-0x4000) * 0x10001 + (0x4321-0x4000)
//               = 0x1000 * 0x10001 + 0x321
//               = 0x10001000 + 0x321
//               = 0x10001321
//
// Resulting X = 0x10001321 is well above kL (0x800000), so Renorm is a
// no-op. The tgt is all-zero on purpose so adapt8 drags the CDF toward
// zero — we don't depend on the post-adapt CDF for this assertion, only
// on the decode math.
func TestGetSym8UniformSlotMid(t *testing.T) {
	var cdf Sym8
	init_sym8(cdf[:])
	var tgt [8][8]uint16
	r := &Rans{X: 0x8000C321, OK: true}
	sym := r.GetSym8(cdf[:], 7, tgt)
	if sym != 4 {
		t.Fatalf("sym = %d, want 4 (slot 0x4321 falls in [0x4000, 0x5000))", sym)
	}
	if r.X != 0x10001321 {
		t.Fatalf("X = 0x%x, want 0x10001321", r.X)
	}
}

// TestGetSym8UniformSlotZero covers the lower boundary. X=0x80008000
// gives slot=0 (since 0x8000 & 0x7FFF = 0) and quo=0x10001 (bit 31 + bit 15
// set, same shape as the X=0x8000C321 case). sym=0 and X=(0x1000-0)*0x10001
// = 0x10001000. No renorm (X >= kL).
func TestGetSym8UniformSlotZero(t *testing.T) {
	var cdf Sym8
	init_sym8(cdf[:])
	var tgt [8][8]uint16
	r := &Rans{X: 0x80008000, OK: true}
	sym := r.GetSym8(cdf[:], 7, tgt)
	if sym != 0 {
		t.Fatalf("sym = %d, want 0", sym)
	}
	if r.X != 0x10001000 {
		t.Fatalf("X = 0x%x, want 0x10001000", r.X)
	}
}

// TestGetSym8SlotAtBoundary covers slot exactly equal to cdf[last-1].
// find16 walks through j=1..7 looking for cdf[j] > slot; every cdf[j]
// is <= slot at the boundary so find16 returns last=8. Then end falls
// back to 0x8000 (the i<8 guard fails), so the symbol's effective
// frequency is 0x8000 - cdf[7] = 0x1000 — same as a uniform mid-symbol,
// but sym = last-1 = 7.
//
// X = 0x8000F000: bits 31 and 15 set, plus 0x7000 in the slot. So
// quo = 0x10001, slot = 0x7000. New X = (0x8000-0x7000)*0x10001 + 0
// = 0x10001000.
func TestGetSym8SlotAtBoundary(t *testing.T) {
	var cdf Sym8
	init_sym8(cdf[:])
	var tgt [8][8]uint16
	r := &Rans{X: 0x8000F000, OK: true} // slot = 0x7000 = cdf[7]
	sym := r.GetSym8(cdf[:], 7, tgt)
	if sym != 7 {
		t.Fatalf("sym = %d, want 7 (slot=cdf[last-1] falls through find16)", sym)
	}
	if r.X != 0x10001000 {
		t.Fatalf("X = 0x%x, want 0x10001000", r.X)
	}
}

// TestDecodeSymbolWrapper verifies DecodeSymbol forwards to GetSym8 with
// the supplied tgt and shift, returning the same result. Same inputs as
// TestGetSym8UniformSlotMid → expect sym=4 and X=0x10001321.
func TestDecodeSymbolWrapper(t *testing.T) {
	var cdf Sym8
	init_sym8(cdf[:])
	var tgt [8][8]uint16
	r := &Rans{X: 0x8000C321, OK: true}
	sym := r.DecodeSymbol(&cdf, tgt, 7)
	if sym != 4 {
		t.Fatalf("DecodeSymbol sym = %d, want 4", sym)
	}
	if r.X != 0x10001321 {
		t.Fatalf("DecodeSymbol X = 0x%x, want 0x10001321", r.X)
	}
}

// TestGetNibbleUniformSameMath runs the 16-slot version with the same
// hand-computed inputs as TestGetSym8UniformSlotMid. Uniform 16-slot CDF
// [0, 0x800, 0x1000, …, 0x7800]; slot=0x4321 falls in [0x4000, 0x4800),
// so sym = 8 (the 16-slot analog of "halfway"). State update matches
// GetSym8 shape but with a 0x800-wide symbol:
//
//	X = (0x4800-0x4000) * 0x10001 + (0x4321-0x4000)
//	  = 0x800 * 0x10001 + 0x321
//	  = 0x8000800 + 0x321
//	  = 0x8000B21
func TestGetNibbleUniformSameMath(t *testing.T) {
	var cdf Nibble16
	init_nibble(cdf[:])
	var tgt [16][16]uint16
	r := &Rans{X: 0x8000C321, OK: true}
	sym := r.GetNibble(cdf[:], 16, 5, tgt)
	if sym != 8 {
		t.Fatalf("sym = %d, want 8 (slot 0x4321 in [0x4000, 0x4800))", sym)
	}
	if r.X != 0x8000B21 {
		t.Fatalf("X = 0x%x, want 0x8000B21", r.X)
	}
}

// TestDecodeNibbleWrapper: DecodeNibble forwards to GetNibble with last=16.
// Same shape as TestDecodeSymbolWrapper but for the 16-slot path.
func TestDecodeNibbleWrapper(t *testing.T) {
	var cdf Nibble16
	init_nibble(cdf[:])
	var tgt [16][16]uint16
	r := &Rans{X: 0x8000C321, OK: true}
	sym := r.DecodeNibble(&cdf, tgt, 5)
	if sym != 8 {
		t.Fatalf("DecodeNibble sym = %d, want 8", sym)
	}
	if r.X != 0x8000B21 {
		t.Fatalf("DecodeNibble X = 0x%x, want 0x8000B21", r.X)
	}
}

// TestGetSym8Underrun: r.OK=false short-circuits with -1 and does not
// touch X. Mirrors the underrun guard in GetBit (state.go:43-45).
func TestGetSym8Underrun(t *testing.T) {
	var cdf Sym8
	init_sym8(cdf[:])
	r := &Rans{X: 0x8000C321, OK: false}
	var tgt [8][8]uint16
	sym := r.GetSym8(cdf[:], 7, tgt)
	if sym != -1 {
		t.Fatalf("underrun sym = %d, want -1", sym)
	}
	if r.X != 0x8000C321 {
		t.Fatalf("underrun must not touch X, got 0x%x", r.X)
	}
}

// TestFind16Boundary: when slot exactly equals the last CDF entry,
// find16 walks through j=1..last-1 without finding any entry > slot
// and returns last. Callers subtract 1 to get the 0-based symbol.
func TestFind16Boundary(t *testing.T) {
	cdf := []uint16{0, 0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000}
	if i := find16(cdf, 0x7000, 8); i != 8 {
		t.Fatalf("find16 at boundary returned %d, want 8", i)
	}
}

// TestAdapt8NoOpWhenTargetMatches: when tgt[sym][j] == cdf[j] for all j,
// d = 0 and adapt is a no-op. Confirms the d computation and the
// >>= shift don't drag the CDF when there's nothing to drag toward.
func TestAdapt8NoOpWhenTargetMatches(t *testing.T) {
	var cdf Sym8
	init_sym8(cdf[:])
	snap := cdf
	tgt := [8][8]uint16{}
	for i := 0; i < 8; i++ {
		copy(tgt[i][:], cdf[:])
	}
	adapt8(cdf[:], 3, tgt, 7)
	for i := 0; i < 8; i++ {
		if cdf[i] != snap[i] {
			t.Fatalf("adapt8 should be no-op when tgt matches CDF, cdf[%d]=0x%04x want 0x%04x",
				i, cdf[i], snap[i])
		}
	}
}

// TestAdapt8ClampsSym: the C++ clamps sym to [0,7] (main.cpp:272-273).
// Out-of-range inputs — negative or >7 — must produce the same result
// as the in-range clamped value, not panic and not silently no-op.
func TestAdapt8ClampsSym(t *testing.T) {
	var cdfA, cdfB Sym8
	init_sym8(cdfA[:])
	init_sym8(cdfB[:])
	var tgt [8][8]uint16
	for i := range 8 {
		for j := range 8 {
			tgt[i][j] = uint16((i + j) * 0x100)
		}
	}
	adapt8(cdfA[:], -1, tgt, 5) // clamps to 0
	adapt8(cdfB[:], 0, tgt, 5)
	for i := 0; i < 8; i++ {
		if cdfA[i] != cdfB[i] {
			t.Fatalf("adapt8 negative-clamp: cdfA[%d]=0x%04x want cdfB[%d]=0x%04x",
				i, cdfA[i], i, cdfB[i])
		}
	}

	var cdfC, cdfD Sym8
	init_sym8(cdfC[:])
	init_sym8(cdfD[:])
	adapt8(cdfC[:], 100, tgt, 5) // clamps to 7
	adapt8(cdfD[:], 7, tgt, 5)
	for i := 0; i < 8; i++ {
		if cdfC[i] != cdfD[i] {
			t.Fatalf("adapt8 over-clamp: cdfC[%d]=0x%04x want cdfD[%d]=0x%04x",
				i, cdfC[i], i, cdfD[i])
		}
	}
}

// TestMixCDFProperties pins the math of the C++ mix_cdf formula so a
// future port can verify it matches the cls-magic2 PE exactly. The
// formula is:
//
//	mixed[i] = ((w * A[i]) >> 16) + ((nw * B[i]) >> 16)
//	          where nw = (uint16_t)(0u - w)
//
// Three regimes we care about:
//
//	w = 0     → nw = 0, both terms zero, mixed[i] = 0. (NOT A or B.)
//	w = 0x8000 → nw = 0x8000; for A==B, w*X + nw*X = 0x10000*X, >> 16
//	           = X. So mixed == A exactly when A == B.
//	w = 0xFFFF → nw = 1; for A[i] = 0x0800, (0xFFFF * 0x0800) >> 16
//	           = 0x7FF (since 0xFFFF*0x800 = 0x7FFF800, and
//	           0x7FFF800 >> 16 = 0x7FF), plus (1 * 0x0800) >> 16 = 0,
//	           so mixed = 0x7FF — close to A[i] but quantized down by 1.
//	           The formula is "almost preserves" at the boundary but
//	           loses one ULP. Worth flagging for PE cross-check.
func TestMixCDFProperties(t *testing.T) {
	var a, b Nibble16
	init_nibble(a[:])
	init_nibble(b[:])

	// w = 0: everything collapses to zero (both terms vanish).
	var mixZero [16]uint16
	mixCDF(mixZero[:], a[:], b[:], 0)
	for i := 0; i < 16; i++ {
		if mixZero[i] != 0 {
			t.Fatalf("w=0 mixed[%d]=0x%04x, want 0", i, mixZero[i])
		}
	}

	// w = 0x8000 with A==B: mixed == A exactly (midpoint identity).
	var mixMid [16]uint16
	mixCDF(mixMid[:], a[:], b[:], 0x8000)
	for i := 0; i < 16; i++ {
		if mixMid[i] != a[i] {
			t.Fatalf("w=0x8000 A==B mixed[%d]=0x%04x, want a[%d]=0x%04x",
				i, mixMid[i], i, a[i])
		}
	}

	// w = 0xFFFF: close to A but quantized. For A[i]=0x0800 the result
	// is 0x7FF, one less than 0x0800. This is what makes the
	// cls-magic2 mix formula suspect — the upstream PE may use a
	// different weight convention. See report note on mix fidelity.
	var mixHi [16]uint16
	mixCDF(mixHi[:], a[:], b[:], 0xFFFF)
	if mixHi[1] != 0x7FF {
		t.Fatalf("w=0xFFFF A==B mixed[1]=0x%04x, want 0x7FF (one ULP below A[1]=0x0800)",
			mixHi[1])
	}
}

// TestGetNibbleMixUniform: with a==b and w=0x8000 (midpoint), the mix
// is exactly a, so GetNibbleMix produces the same result as plain
// GetNibble on a. Use the same X=0x8000C321, slot=0x4321 inputs as
// TestGetNibbleUniformSameMath — the sym and X match. The weight w
// moves per GetNibbleMix's update rule, which is
//
//	w2 = w - (w >> 4)
//	if fA >= fB: w2 += 0xFFF
//
// For uniform A==B at sym=8 (i=9), fA = a[9]-a[8] = 0x4800-0x4000 = 0x800,
// fB = same. The condition is `>=`, not `>`, so fA==fB triggers the
// +0xFFF add — w2 ends up at 0x7800 + 0xFFF = 0x87FF, not 0x7800.
//
// X = (0x4800-0x4000) * 0x10001 + (0x4321-0x4000)
//   = 0x800 * 0x10001 + 0x321
//   = 0x8000800 + 0x321
//   = 0x8000B21
func TestGetNibbleMixUniform(t *testing.T) {
	var a, b Nibble16
	init_nibble(a[:])
	init_nibble(b[:])
	var tgt [16][16]uint16
	for i := 0; i < 16; i++ {
		copy(tgt[i][:], a[:])
	}
	var w uint16 = 0x8000
	r := &Rans{X: 0x8000C321, OK: true}
	sym := r.GetNibbleMix(a[:], b[:], &w, 16, 5, tgt)
	if sym != 8 {
		t.Fatalf("sym = %d, want 8", sym)
	}
	wantX := uint32(0x800)*uint32(0x10001) + uint32(0x321)
	if r.X != wantX {
		t.Fatalf("X = 0x%x, want 0x%x", r.X, wantX)
	}
	// w2 = (w - (w>>4)) + 0xFFF = 0x7800 + 0xFFF = 0x87FF. Note the
	// `>=` (not `>`) in the C++ condition — uniform A==B still adds.
	wantW := uint16(0x8000-(0x8000>>4)) + 0xFFF
	if w != wantW {
		t.Fatalf("w = 0x%04x, want 0x%04x (fA==fB still triggers >= add)", w, wantW)
	}
}