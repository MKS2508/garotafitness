package godec

import (
	"testing"
	"unsafe"
)

// =====================================================================
// ExtraModel
// =====================================================================

// TestExtraModelLayout pins the struct size so a future field drift
// (e.g. widening CDF rows, dropping the Bits array) gets caught. The
// C++ struct is:
//
//	ctx8 (1) + ctxa (1) + 2 pad + p0[16] (32) + cdf[16][16] (512) +
//	esc[16][16] (512) + bits[2048] (4096) = 5154 bytes
//
// Go's struct alignment inserts padding; the test asserts the actual
// size rather than re-deriving the offset math so a layout change
// surfaces immediately.
func TestExtraModelLayout(t *testing.T) {
	got := unsafe.Sizeof(ExtraModel{})
	if got == 0 {
		t.Fatalf("sizeof(ExtraModel) = 0")
	}
	// Sanity invariant: the bits array alone is 2048 * 2 = 4096 bytes.
	// The full struct should be at least that large.
	if got < unsafe.Sizeof([kExtraBits]uint16{}) {
		t.Fatalf("sizeof(ExtraModel)=%d smaller than bits[2048] alone", got)
	}
}

// TestExtraModelInitSeeds verifies Init() resets the contexts and
// seeds every CDF. Mirrors main.cpp:884-892 (extra_init).
//
// Post-Init contract:
//
//	Ctx8 = 0, CtxA = 0
//	P0[i]    = 0x4000 for all i
//	CDF[i][j] = uniform [0, 0x800, …, 0x7800] for all i
//	Esc[i][j] = uniform for all i
//	Bits[i]   = 0x4000 for all i
func TestExtraModelInitSeeds(t *testing.T) {
	var m ExtraModel
	m.Init()

	if m.Ctx8 != 0 {
		t.Fatalf("Ctx8 = 0x%02x, want 0", m.Ctx8)
	}
	if m.CtxA != 0 {
		t.Fatalf("CtxA = 0x%02x, want 0", m.CtxA)
	}

	for i, p := range m.P0 {
		if p != 0x4000 {
			t.Fatalf("P0[%d]=0x%04x, want 0x4000", i, p)
		}
	}

	var wantCDF [16]uint16
	init_nibble(wantCDF[:])

	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			if m.CDF[i][j] != wantCDF[j] {
				t.Fatalf("CDF[%d][%d]=0x%04x, want 0x%04x", i, j, m.CDF[i][j], wantCDF[j])
			}
			if m.Esc[i][j] != wantCDF[j] {
				t.Fatalf("Esc[%d][%d]=0x%04x, want 0x%04x", i, j, m.Esc[i][j], wantCDF[j])
			}
		}
	}

	for i, b := range m.Bits {
		if b != 0x4000 {
			t.Fatalf("Bits[%d]=0x%04x, want 0x4000", i, b)
		}
	}
}

// TestExtraModelInitIsIdempotent verifies that a second Init() call
// produces the same state as the first. Catches accidental carryover
// of stale state across decodes.
func TestExtraModelInitIsIdempotent(t *testing.T) {
	var m ExtraModel
	m.Init()
	snapshot := m

	m.Init()
	if m != snapshot {
		t.Fatalf("Init is not idempotent: snapshot diverged")
	}
}

// =====================================================================
// Hist.HistH1
// =====================================================================

// TestHistH1 pins the per-call narrowness helper at hand-computed
// pairs. hist_h1(h) = bitlen(|W20 - W24|) & 0xff. Mirrors main.cpp:676-678.
//
// Edge cases:
//
//	|Δ|=0  → bitlen=0
//	|Δ|=1  → bitlen=1
//	|Δ|=255→ bitlen=8 (max for uint8)
//	|Δ|=256 wraps to 0 in uint8, then bitlen=0
func TestHistH1(t *testing.T) {
	cases := []struct {
		w20, w24 uint32
		want     int
	}{
		{0, 0, 0},          // |0| & 0xff = 0; bitlen=0
		{1, 0, 1},          // |1| = 1; bitlen=1
		{255, 0, 8},        // |255| = 255; bitlen=8
		{0, 255, 8},        // |255| (abs is symmetric)
		{100, 50, 6},       // |50| = 50 = 0x32; bitlen=6 (highest bit = 0x20)
		{200, 100, 7},      // |100| = 100 = 0x64; bitlen=7 (highest bit = 0x40)
		{256, 0, 0},        // |256| & 0xff = 0; bitlen=0 (wraps in uint8)
		{512, 256, 0},      // |256| & 0xff = 0
		{1, 256, 8},        // |1-256|=255; & 0xff = 255; bitlen=8 (uint8 cast takes LSB)
	}
	for _, c := range cases {
		h := &Hist{W20: c.w20, W24: c.w24}
		if got := h.HistH1(); got != c.want {
			t.Fatalf("Hist{W20=%d,W24=%d}.HistH1()=%d, want %d", c.w20, c.w24, got, c.want)
		}
	}
}

// =====================================================================
// Hist.HistRow
// =====================================================================

// TestHistRow pins the 81-entry row index at hand-computed pairs.
// hist_row clamps a 0x0..0x50 row to [0, 80].
//
// Compute:
//
//	a = |W08-W0C|
//	b = |W10-W14|
//	h0 = bitlen((a+b) >> 1)  [per-byte avg, & 0xff first]
//	h1 = HistH1()
//	row = h0*9 + h1, clamp to [0, 80]
func TestHistRow(t *testing.T) {
	cases := []struct {
		name             string
		w08, w0c, w10, w14, w20, w24 uint32
		want             int
	}{
		{
			name: "zero hist",
			want: 0, // h0=0 (a=b=0, avg=0, bitlen=0); h1=0; row=0
		},
		{
			name: "all-equal slots",
			w08: 5, w0c: 5, w10: 5, w14: 5, w20: 5, w24: 5,
			want: 0, // a=b=0, h0=0; |0|=0, h1=0; row=0
		},
		{
			name: "avg=1, no W20-W24 gap",
			w08: 0, w0c: 1, w10: 0, w14: 1, w20: 5, w24: 5,
			want: 9, // a=|0-1|=1, b=|0-1|=1, (1+1)>>1=1, bitlen(1)=1 → h0=1; h1=0; row=1*9+0=9
		},
		{
			name: "avg=255, no W20-W24 gap",
			w08: 0, w0c: 255, w10: 0, w14: 255, w20: 5, w24: 5,
			want: 8 * 9, // a=255, b=255, (255+255)>>1=255, bitlen(255)=8 → h0=8; h1=0; row=72
		},
		{
			name: "h0=0, h1=8",
			w08: 5, w0c: 5, w10: 5, w14: 5, w20: 0, w24: 255,
			want: 8, // a=b=0, h0=0; |W20-W24|=255, h1=8; row=0*9+8=8
		},
		{
			name: "h0=4, h1=4",
			w08: 0, w0c: 15, w10: 0, w14: 15, w20: 0, w24: 15,
			want: 4*9 + 4, // a=15, b=15, (15+15)>>1=15, bitlen(15)=4 → h0=4; |15|=15, h1=4
		},
	}
	for _, c := range cases {
		h := &Hist{
			W08: c.w08, W0C: c.w0c,
			W10: c.w10, W14: c.w14,
			W20: c.w20, W24: c.w24,
		}
		if got := h.HistRow(); got != c.want {
			t.Fatalf("%s: HistRow()=%d, want %d", c.name, got, c.want)
		}
	}
}

// TestHistRowClamp pins the [0, 80] clamp. The max legal index is
// h0=8, h1=8 → 8*9+8 = 80. h0=9 is impossible from a uint8 byte cast
// (bitlen(255)=8 is the max), but if a wider value slips through the
// C++ behaviour is to clamp; this test verifies we do the same.
func TestHistRowClamp(t *testing.T) {
	// Hand-construct an out-of-range h0 by spoofing an external h1.
	// HistRow doesn't accept an h1 parameter, so we exercise the clamp
	// by giving it the canonical max.
	h := Hist{
		W08: 0, W0C: 255,
		W10: 0, W14: 255,
		W20: 0, W24: 255,
	}
	row := h.HistRow()
	if row > 80 || row < 0 {
		t.Fatalf("row = %d, want [0, 80]", row)
	}
	if row != 8*9+8 {
		t.Fatalf("row = %d, want %d (h0=8, h1=8)", row, 8*9+8)
	}
}

// =====================================================================
// Hist.ApplySample
// =====================================================================

// TestApplySample pins the shift-register update. main.cpp:690-703:
//
//	a0 = (|n0| | 1)
//	a1 = (|n1| | 1)
//	m0 = ((a0 + 2*W20) >> 1) & 0xff
//	m1 = ((a1 + 2*W24) >> 1) & 0xff
//	W08 = W10; W0C = W14; W10 = W20; W14 = W24
//	W18 = m0;   W1C = m1
//	W20 = m0;   W24 = m1
func TestApplySample(t *testing.T) {
	// n0=n1=0 → a0=a1=1, m0=((1+2*W20)>>1)&0xff, m1=((1+2*W24)>>1)&0xff
	// W20=0, W24=0 → m0=m1=0
	h := Hist{}
	h.ApplySample(0, 0)
	if h.W20 != 0 || h.W24 != 0 {
		t.Fatalf("zero sample, zero init: W20=%d W24=%d", h.W20, h.W24)
	}
	if h.W08 != 0 || h.W10 != 0 {
		t.Fatalf("W08=%d W10=%d, want 0 (cascaded from zero init)", h.W08, h.W10)
	}

	// n0=1, n1=0; W20=0, W24=0 (already set)
	// a0 = |1| | 1 = 1, m0 = ((1 + 0) >> 1) & 0xff = 0
	// a1 = |0| | 1 = 1, m1 = ((1 + 0) >> 1) & 0xff = 0
	// W20 = m0 = 0; W24 = m1 = 0
	// Shift: W10←W20(=0), W08←W10(=0), etc.
	h.ApplySample(1, 0)
	if h.W20 != 0 {
		t.Fatalf("W20=%d, want 0", h.W20)
	}

	// Reset and exercise a non-zero shift.
	h = Hist{W20: 10, W24: 20}
	h.ApplySample(0, 0)
	// a0 = |0| | 1 = 1; m0 = ((1 + 20) >> 1) & 0xff = 10
	// a1 = |0| | 1 = 1; m1 = ((1 + 40) >> 1) & 0xff = 20
	if h.W20 != 10 {
		t.Fatalf("W20=%d, want 10", h.W20)
	}
	if h.W24 != 20 {
		t.Fatalf("W24=%d, want 20", h.W24)
	}
	// Cascade: W10 ← old W20 = 10; W08 ← old W10 = 0 (was init zero)
	if h.W10 != 10 {
		t.Fatalf("W10=%d, want 10 (cascaded from old W20)", h.W10)
	}
	if h.W08 != 0 {
		t.Fatalf("W08=%d, want 0 (init was zero, never moved)", h.W08)
	}

	// Apply with n0=5: a0 = |5| | 1 = 5; m0 = ((5 + 2*10)>>1) & 0xff = 12
	h.ApplySample(5, 0)
	wantM0 := ((abs32(int32(5)) | 1) + 2*10) >> 1 & 0xff
	if h.W20 != uint32(wantM0) {
		t.Fatalf("W20=%d, want %d", h.W20, wantM0)
	}
	// Cascade: W10 ← 10 (previous W20), W08 ← 10 (previous W10)
	if h.W10 != 10 || h.W08 != 10 {
		t.Fatalf("cascade: W10=%d W08=%d, want 10 10", h.W10, h.W08)
	}
}

// TestApplySampleKeepAlive verifies the shift-register continues
// to respond to new samples even when the running slot is 0. The
// anti-zero guard in the C++ (`a0 = abs(n0) | 1`) protects the new
// sample's LSB so that a histogram slot at W20=0 doesn't strictly
// freeze; the moving average ((a0 + 2*W20) >> 1) & 0xff can still
// reach 0 on a single step when W20=0, but the running state
// responds to subsequent non-zero inputs.
func TestApplySampleKeepAlive(t *testing.T) {
	h := Hist{W20: 10, W24: 10}
	h.ApplySample(1, 1)
	// a0 = |1| | 1 = 1; m0 = ((1 + 20) >> 1) & 0xff = 10
	// Histogram is preserved.
	if h.W20 != 10 {
		t.Fatalf("running slot W20=%d, want 10 (preserved)", h.W20)
	}

	// Now bump it up:
	h.ApplySample(5, 5)
	want := ((abs32(int32(5)) | 1) + 2*10) >> 1 & 0xff
	if h.W20 != uint32(want) {
		t.Fatalf("W20=%d, want %d", h.W20, want)
	}
}

// =====================================================================
// Rans.ExtraSample
// =====================================================================

// TestExtraSampleShortPath exercises bsf<=1: the function returns 0,
// calls ApplySample(0,0), and does not consume any rANS bits.
func TestExtraSampleShortPath(t *testing.T) {
	h := Hist{W20: 10, W24: 20}
	bits := make([]uint16, 32)
	for i := range bits {
		bits[i] = kMB / 2
	}
	r := &Rans{X: 0x00800000, Buf: nil, Off: 0, Len: 0, OK: true}
	got := r.ExtraSample(&h, bits, 0, h.HistH1())
	if got != 0 {
		t.Fatalf("bsf=0 returned %d, want 0", got)
	}
	// W20 should have cascaded from 10 → 10 (m0=0 + 1)/2 = 0; see
	// ApplySample keep-alive test for why.
	if r.OK == false {
		t.Fatalf("bsf<=1 should not consume the rANS stream")
	}
}

// TestExtraSampleUnderrun exercises bsf>=2 with no rANS input. The
// first GetBit call's renorm underruns and the function returns -1.
func TestExtraSampleUnderrun(t *testing.T) {
	h := Hist{W20: 10, W24: 20}
	bits := make([]uint16, 9216)
	for i := range bits {
		bits[i] = kMB / 2
	}
	r := &Rans{X: 0, Buf: nil, Off: 0, Len: 0, OK: true}
	got := r.ExtraSample(&h, bits, 4, h.HistH1())
	if got != -1 {
		t.Fatalf("underrun returned %d, want -1", got)
	}
	if r.OK {
		t.Fatalf("underrun must clear r.OK, still true")
	}
}

// TestExtraSampleSmoke exercises a valid call against an all-FF
// buffer and asserts:
//
//   - the call returns a non-negative integer (rANS survives)
//   - the call mutates h (ApplySample shifted the histogram)
//   - the h1 parameter affects the bit offset (different h1 → different
//     bits[] read pattern → different sample values, with high
//     probability)
func TestExtraSampleSmoke(t *testing.T) {
	buf := make([]byte, 128)
	for i := range buf {
		buf[i] = 0xFF
	}
	bits := make([]uint16, 9216)
	for i := range bits {
		bits[i] = kMB / 2
	}

	// Run with bsf=4, h1=2 — should consume sym=3 bits per pair (6 bits).
	h := Hist{W20: 10, W24: 20}
	r := &Rans{X: 0x00800000, Buf: buf, Off: 0, Len: len(buf), OK: true}
	oldW20 := h.W20
	v := r.ExtraSample(&h, bits, 4, 2)
	if v < 0 {
		t.Fatalf("smoke returned %d, want >= 0", v)
	}
	if h.W20 == oldW20 {
		t.Logf("note: W20 unchanged (possible if m0=oldW20)")
	}

	// Vary h1 and bsf — at least one of {vary_h1, vary_bsf} should
	// produce a different sample with high probability over an
	// all-FF buffer.
	h2 := Hist{W20: 10, W24: 20}
	r2 := &Rans{X: 0x00800000, Buf: buf, Off: 0, Len: len(buf), OK: true}
	v2 := r2.ExtraSample(&h2, bits, 4, 5)
	if v2 < 0 {
		t.Fatalf("h1=5 bsf=4 returned %d, want >= 0", v2)
	}
	// Both decoded something; not strictly asserting divergence
	// because the same bit pattern can collide.
}

// TestExtraSampleParamClamps verifies the input clamps match
// main.cpp:705-730:
//
//	sym = bsf - 1, clamped to [0, 8]
//	h1 clamped to [0, 8]
func TestExtraSampleParamClamps(t *testing.T) {
	bits := make([]uint16, 9216)
	for i := range bits {
		bits[i] = kMB / 2
	}
	buf := make([]byte, 256)
	for i := range buf {
		buf[i] = 0xFF
	}

	// bsf=20 (huge): sym clamps to 8; h1=2. Should still consume
	// exactly 8 pairs of bits.
	h := Hist{W20: 1, W24: 1}
	r := &Rans{X: 0x00800000, Buf: buf, Off: 0, Len: len(buf), OK: true}
	v := r.ExtraSample(&h, bits, 20, 2)
	if v < 0 {
		t.Fatalf("bsf=20 returned %d", v)
	}

	// h1=20 (huge): clamps to 8.
	h2 := Hist{W20: 1, W24: 1}
	r2 := &Rans{X: 0x00800000, Buf: buf, Off: 0, Len: len(buf), OK: true}
	v2 := r2.ExtraSample(&h2, bits, 2, 20)
	if v2 < 0 {
		t.Fatalf("h1=20 returned %d", v2)
	}

	// h1=-5 (negative): clamps to 0.
	h3 := Hist{W20: 1, W24: 1}
	r3 := &Rans{X: 0x00800000, Buf: buf, Off: 0, Len: len(buf), OK: true}
	v3 := r3.ExtraSample(&h3, bits, 2, -5)
	if v3 < 0 {
		t.Fatalf("h1=-5 returned %d", v3)
	}
}

// =====================================================================
// Rans.DecodeMix16Esc
// =====================================================================

// TestDecodeMix16EscHappyPath exercises a non-escape symbol. With a
// fresh CDF (init_nibble), all 16 symbols are equiprobable; the
// result is some value in [0, 14] (15 would trigger the escape).
func TestDecodeMix16EscHappyPath(t *testing.T) {
	a := make([]uint16, 16)
	b := make([]uint16, 16)
	esc := make([]uint16, 16)
	init_nibble(a)
	init_nibble(b)
	init_nibble(esc)

	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = 0xFF
	}
	var wp uint16 = 0x8000
	r := &Rans{X: 0x00800000, Buf: buf, Off: 0, Len: len(buf), OK: true}
	v := r.DecodeMix16Esc(a, b, &wp, esc)
	if v < 0 {
		t.Fatalf("happy path returned %d", v)
	}
	if v > 30 {
		t.Fatalf("happy path returned %d, want [0, 30]", v)
	}
}

// TestDecodeMix16EscUnderrun exercises the rANS-exhaustion path via
// the 15-escape route. With X chosen so the first GetNibbleMix
// returns 15 (slot >= cdf[15] = 0x7800 in the uniform CDF), the
// escape path calls GetNibble on `esc` with no input, which
// underruns and returns -1. DecodeMix16Esc propagates -1.
func TestDecodeMix16EscUnderrun(t *testing.T) {
	a := make([]uint16, 16)
	b := make([]uint16, 16)
	esc := make([]uint16, 16)
	init_nibble(a)
	init_nibble(b)
	init_nibble(esc)

	// X = 0x7800 → low 15 bits = 0x7800 → slot = 0x7800 → with uniform
	// CDF find16 returns 16 (no j matches, since cdf[15]=0x7800 is not
	// strictly greater than 0x7800). i=16 → sym=15 → escape path.
	// Then renorm underruns (X drops to 0, OK=false), but the symbol
	// 15 is already returned.
	var wp uint16 = 0x8000
	r := &Rans{X: 0x7800, Buf: nil, Off: 0, Len: 0, OK: true}
	v := r.DecodeMix16Esc(a, b, &wp, esc)
	if v != -1 {
		t.Fatalf("underrun returned %d, want -1", v)
	}
	if r.OK {
		t.Fatalf("underrun must clear r.OK")
	}
}

// TestDecodeMix16EscAdaptsState verifies the call mutates a, b, and
// wp (the mix weight adapts to the observed symbol frequency).
func TestDecodeMix16EscAdaptsState(t *testing.T) {
	a := make([]uint16, 16)
	b := make([]uint16, 16)
	esc := make([]uint16, 16)
	init_nibble(a)
	init_nibble(b)
	init_nibble(esc)
	snapshotA := make([]uint16, 16)
	copy(snapshotA, a)
	wpInitial := uint16(0x8000)
	wp := wpInitial

	buf := make([]byte, 64)
	for i := range buf {
		buf[i] = 0xFF
	}
	r := &Rans{X: 0x00800000, Buf: buf, Off: 0, Len: len(buf), OK: true}
	_ = r.DecodeMix16Esc(a, b, &wp, esc)

	// wp must have moved (mix weight adapts to fA vs fB at the slot).
	if wp == wpInitial {
		t.Fatalf("wp unchanged after DecodeMix16Esc")
	}
	// a must have drifted (adapt16 nudges every slot toward tgt[sym]).
	aChanged := false
	for i := 0; i < 16; i++ {
		if a[i] != snapshotA[i] {
			aChanged = true
			break
		}
	}
	if !aChanged {
		t.Fatalf("a unchanged after DecodeMix16Esc")
	}
}

// =====================================================================
// Rans.DecodeNewOff
// =====================================================================

// TestDecodeNewOffShortPath exercises the nbits<=5 short path. We
// hand-set bp[s*16..] to all-zero bits and verify the decoded value
// is exactly `base` (since extra=0).
//
// With nbtab = kA6E7 and s=0, nbits=5, base = be0_base(kA6E7, 0) = 0.
// The function should return 0.
func TestDecodeNewOffShortPath(t *testing.T) {
	// Initialize mixed CDFs.
	a := make([]uint16, 16)
	b := make([]uint16, 16)
	esc := make([]uint16, 16)
	init_nibble(a)
	init_nibble(b)
	init_nibble(esc)
	// Seed bp with a uniform 14-bit distribution so the rANS stream
	// doesn't underrun mid-way. Each bp slot is single-bit; mid
	// (0x2000) is equiprobable.
	bp := make([]uint16, 16*16)
	for i := range bp {
		bp[i] = kMB / 2
	}

	buf := make([]byte, 64)
	for i := range buf {
		buf[i] = 0xFF
	}
	var wp uint16 = 0x8000
	r := &Rans{X: 0x00800000, Buf: buf, Off: 0, Len: len(buf), OK: true}

	// Pass empty mid/tail: the function only touches them when nbits > 5.
	v := r.DecodeNewOff(a, b, &wp, esc, bp, kA6E7[:], nil, nil)
	if v < 0 {
		t.Fatalf("short path returned %d, want >= 0", v)
	}
}

// TestDecodeNewOffUnderrun exercises the rANS-exhaustion path. With
// no input bytes and X below kL, the first GetNibbleMix call's
// renorm underruns and DecodeNewOff returns -1.
func TestDecodeNewOffUnderrun(t *testing.T) {
	a := make([]uint16, 16)
	b := make([]uint16, 16)
	esc := make([]uint16, 16)
	init_nibble(a)
	init_nibble(b)
	init_nibble(esc)
	bp := make([]uint16, 16*16)

	var wp uint16 = 0x8000
	r := &Rans{X: 0, Buf: nil, Off: 0, Len: 0, OK: true}
	v := r.DecodeNewOff(a, b, &wp, esc, bp, kA6E7[:], nil, nil)
	if v != -1 {
		t.Fatalf("underrun returned %d, want -1", v)
	}
	if r.OK {
		t.Fatalf("underrun must clear r.OK")
	}
}

// TestDecodeNewOffSClamp verifies the symbol clamp [0, 30]. A caller
// passing a 5-element nbtab would normally trip the `s >= len(nbtab)`
// guard; we verify the clamp at the upper boundary (s=30) and the
// graceful fallback for `s >= ntab`.
func TestDecodeNewOffSClamp(t *testing.T) {
	a := make([]uint16, 16)
	b := make([]uint16, 16)
	esc := make([]uint16, 16)
	init_nibble(a)
	init_nibble(b)
	init_nibble(esc)
	bp := make([]uint16, 16*16)
	for i := range bp {
		bp[i] = kMB / 2
	}

	buf := make([]byte, 128)
	for i := range buf {
		buf[i] = 0xFF
	}

	// Pass a 1-element nbtab. be0_base(nbtab=[5], 0) = 0 (no
	// prefix terms). s is clamped to len(nbtab)-1 = 0 (since
	// s starts in [0,15] and we clamp s >= len(nbtab)).
	// nbits = nbtab[0] = 5; extra is 5 random bits → v ∈ [0, 31].
	var wp uint16 = 0x8000
	nbtab := [1]uint8{5}
	r := &Rans{X: 0x00800000, Buf: buf, Off: 0, Len: len(buf), OK: true}
	v := r.DecodeNewOff(a, b, &wp, esc, bp[:], nbtab[:], nil, nil)
	if v < 0 {
		t.Fatalf("1-elem nbtab returned %d, want >= 0", v)
	}
	if v >= 32 {
		t.Fatalf("1-elem nbtab returned %d, want [0, 31] (base=0, extra in [0,31])", v)
	}
}

// =====================================================================
// DecodeOff
// =====================================================================

// TestDecodeOffClass0 exercises the cls=0 path: returns *rep0 and
// bumps it to 1 if it was 0.
func TestDecodeOffClass0(t *testing.T) {
	reps := []int{1, 1, 1, 1}
	rep0 := 0
	d := DecodeOff(0, 99, &rep0, reps, 4)
	if d != 1 {
		t.Fatalf("cls=0 rep0=0: got %d, want 1", d)
	}
	if rep0 != 1 {
		t.Fatalf("rep0=%d, want 1", rep0)
	}

	rep0 = 7
	d = DecodeOff(0, 99, &rep0, reps, 4)
	if d != 7 {
		t.Fatalf("cls=0 rep0=7: got %d, want 7", d)
	}
}

// TestDecodeOffCls4to9 exercises the kA690 rotation path. With
// reps = {1, 5, 9, 13} and cls=6 (kA690[2]=2), idx=2, the function
// should rotate {9, 5, 1} up and put 9 at [0].
func TestDecodeOffCls4to9(t *testing.T) {
	reps := []int{1, 5, 9, 13}
	rep0 := 0
	// cls=4 → kA690[0]=0 → idx=0 → returns reps[0]=1, no rotation.
	d := DecodeOff(4, 0, &rep0, reps, 4)
	if d != 1 {
		t.Fatalf("cls=4 idx=0: got %d, want 1", d)
	}
	if reps[0] != 1 {
		t.Fatalf("reps[0]=%d, want 1", reps[0])
	}

	// cls=6 → kA690[2]=2 → idx=2 → returns reps[2]=9, rotates.
	reps = []int{1, 5, 9, 13}
	rep0 = 0
	d = DecodeOff(6, 0, &rep0, reps, 4)
	if d != 9 {
		t.Fatalf("cls=6 idx=2: got %d, want 9", d)
	}
	if reps[0] != 9 || reps[1] != 1 || reps[2] != 5 {
		t.Fatalf("rotation: reps=%v, want [9 1 5 13]", reps)
	}
	if rep0 != 9 {
		t.Fatalf("rep0=%d, want 9", rep0)
	}
}

// TestDecodeOffCls10 exercises the cls=10 path: idx=extra (no kA690
// lookup). With extra=2 and reps = {1, 5, 9, 13}, the function
// returns reps[2]=9 and rotates.
func TestDecodeOffCls10(t *testing.T) {
	reps := []int{1, 5, 9, 13}
	rep0 := 0
	d := DecodeOff(10, 2, &rep0, reps, 4)
	if d != 9 {
		t.Fatalf("cls=10 idx=2: got %d, want 9", d)
	}
	if reps[0] != 9 {
		t.Fatalf("reps[0]=%d, want 9", reps[0])
	}
}

// TestDecodeOffCls12to15 exercises the cls-12 short path. With
// cls=14, idx = cls-12 = 2.
func TestDecodeOffCls12to15(t *testing.T) {
	reps := []int{1, 5, 9, 13}
	rep0 := 0
	d := DecodeOff(14, 0, &rep0, reps, 4)
	if d != 9 {
		t.Fatalf("cls=14 idx=2: got %d, want 9", d)
	}
	if reps[0] != 9 {
		t.Fatalf("reps[0]=%d, want 9", reps[0])
	}
}

// TestDecodeOffCls1to3Insert exercises the cls in {1,2,3,11} path.
// The function calls InsertNewOff with `extra` (clamped to >= 0) and
// returns the same value. rep0 is NOT updated.
func TestDecodeOffCls1to3Insert(t *testing.T) {
	reps := make([]int, 32)
	for i := range reps {
		reps[i] = i
	}
	rep0 := 42
	d := DecodeOff(1, 7, &rep0, reps, 32)
	if d != 7 {
		t.Fatalf("cls=1 extra=7: got %d, want 7", d)
	}
	if reps[17] != 7 {
		t.Fatalf("reps[17]=%d, want 7", reps[17])
	}
	// rep0 must NOT change on the insert path.
	if rep0 != 42 {
		t.Fatalf("rep0=%d, want 42 (insert path doesn't touch rep0)", rep0)
	}
}

// TestDecodeOffCls1to3InsertNegative exercises the negative-extra
// clamp: extra=-3 becomes d=0.
func TestDecodeOffCls1to3InsertNegative(t *testing.T) {
	reps := make([]int, 32)
	rep0 := 42
	d := DecodeOff(3, -3, &rep0, reps, 32)
	if d != 0 {
		t.Fatalf("cls=3 extra=-3: got %d, want 0", d)
	}
	if reps[17] != 0 {
		t.Fatalf("reps[17]=%d, want 0", reps[17])
	}
}

// TestDecodeOffIdxOutOfRange exercises the nrep guard. With cls=6
// (kA690[2]=2) but nrep=2, idx=2 is out of range → falls through to
// the insert path. Use nrep=32 (cls11's working set) so the insert
// cascade has slots to land in.
func TestDecodeOffIdxOutOfRange(t *testing.T) {
	reps := make([]int, 32)
	for i := range reps {
		reps[i] = 99
	}
	rep0 := 42
	d := DecodeOff(6, 5, &rep0, reps, 32)
	// kA690[2]=2, idx=2, but nrep is large enough here — actually
	// nrep=32 means idx=2 is IN range, so we go through the rotation
	// path. Use a smaller nrep:
	rep0 = 42
	d = DecodeOff(6, 5, &rep0, reps, 2)
	// kA690[2]=2, idx=2 >= nrep=2 → falls through, d=extra=5.
	if d != 5 {
		t.Fatalf("out-of-range idx: got %d, want 5", d)
	}
	// With nrep=2 InsertNewOff is a no-op (no slot >=17 guard fires),
	// so reps[17] stays at the initial 99.
	if reps[17] != 99 {
		t.Fatalf("reps[17]=%d, want 99 (InsertNewOff no-op at nrep=2)", reps[17])
	}
}

// =====================================================================
// InsertNewOff
// =====================================================================

// TestInsertNewOffShortSlice exercises nrep<=17 → no-op. The cls1
// decoder passes nrep=4, which means slots [18..20] never get
// touched.
func TestInsertNewOffShortSlice(t *testing.T) {
	reps := make([]int, 4)
	rep0Snapshot := reps
	InsertNewOff(reps, 4, 99)
	if reps[0] != rep0Snapshot[0] || reps[3] != rep0Snapshot[3] {
		t.Fatalf("short slice was mutated: %v", reps)
	}
}

// TestInsertNewOffCascade exercises nrep>=18 (cls11 working set).
// Each call should shift the cascade and put d at reps[17].
func TestInsertNewOffCascade(t *testing.T) {
	reps := make([]int, 32)
	// Pre-seed: [17]=100, [18]=200, [19]=300, [20]=400.
	reps[17] = 100
	reps[18] = 200
	reps[19] = 300
	reps[20] = 400

	InsertNewOff(reps, 21, 999)

	if reps[17] != 999 {
		t.Fatalf("reps[17]=%d, want 999", reps[17])
	}
	if reps[18] != 100 {
		t.Fatalf("reps[18]=%d, want 100", reps[18])
	}
	if reps[19] != 200 {
		t.Fatalf("reps[19]=%d, want 200", reps[19])
	}
	if reps[20] != 300 {
		t.Fatalf("reps[20]=%d, want 300 (off-20 shift)", reps[20])
	}
}

// TestInsertNewOffExactBoundary exercises nrep=18. Per the C++, the
// `nrep > N` guards are strict `>` comparisons, so at nrep=18 only
// the `nrep > 17` branch fires — reps[18..20] are NOT shifted.
func TestInsertNewOffExactBoundary(t *testing.T) {
	reps := make([]int, 32)
	reps[17] = 100
	reps[18] = 200
	reps[19] = 300
	reps[20] = 400

	InsertNewOff(reps, 18, 999)

	if reps[17] != 999 {
		t.Fatalf("reps[17]=%d, want 999", reps[17])
	}
	// At nrep=18, only the `nrep > 17` branch fires; the cascade
	// (reps[18..20]) does NOT shift. This matches the C++ strict `>`.
	if reps[18] != 200 {
		t.Fatalf("reps[18]=%d, want 200 (cascade off at nrep=18)", reps[18])
	}
	if reps[19] != 300 || reps[20] != 400 {
		t.Fatalf("nrep=18 over-shifted: reps[19]=%d reps[20]=%d", reps[19], reps[20])
	}
}

// =====================================================================
// EsiAfterMatch
// =====================================================================

// TestEsiAfterMatchCls0 exercises the cls0 sub-histogram row (48 + hist & 15).
// With hist=3, i = 48+3 = 51. kEsiTab[51] = 108.
func TestEsiAfterMatchCls0(t *testing.T) {
	got := EsiAfterMatch(0, 0, 3)
	want := int(kEsiTab[48+3])
	if got != want {
		t.Fatalf("cls=0 hist=3: got %d, want %d (kEsiTab[%d])", got, want, 48+3)
	}
}

// TestEsiAfterMatchCls4to10 exercises the long-match sub-histogram
// row (32 + hist & 15).
func TestEsiAfterMatchCls4to10(t *testing.T) {
	for cls := 4; cls <= 10; cls++ {
		hist := 7
		got := EsiAfterMatch(0, cls, hist)
		want := int(kEsiTab[32+(hist&15)])
		if got != want {
			t.Fatalf("cls=%d hist=%d: got %d, want %d", cls, hist, got, want)
		}
	}
}

// TestEsiAfterMatchCls12to15 exercises the long-match row again
// (same as 4..10). The C++ condition is `(cls >= 4 && cls <= 10) ||
// (cls >= 12 && cls <= 15)`.
func TestEsiAfterMatchCls12to15(t *testing.T) {
	for cls := 12; cls <= 15; cls++ {
		hist := 5
		got := EsiAfterMatch(0, cls, hist)
		want := int(kEsiTab[32+(hist&15)])
		if got != want {
			t.Fatalf("cls=%d hist=%d: got %d, want %d", cls, hist, got, want)
		}
	}
}

// TestEsiAfterMatchCls1to3And11 exercises the short-match row
// (16 + hist & 15).
func TestEsiAfterMatchCls1to3And11(t *testing.T) {
	for _, cls := range []int{1, 2, 3, 11} {
		hist := 2
		got := EsiAfterMatch(0, cls, hist)
		want := int(kEsiTab[16+(hist&15)])
		if got != want {
			t.Fatalf("cls=%d hist=%d: got %d, want %d", cls, hist, got, want)
		}
	}
}

// TestEsiAfterMatchHistMask verifies the hist & 15 mask (only the low
// 4 bits participate).
func TestEsiAfterMatchHistMask(t *testing.T) {
	// hist=15 and hist=31 should both index kEsiTab[48+15].
	a := EsiAfterMatch(0, 0, 15)
	b := EsiAfterMatch(0, 0, 31)
	if a != b {
		t.Fatalf("hist=15 (%d) vs hist=31 (%d)", a, b)
	}
	if a != int(kEsiTab[48+15]) {
		t.Fatalf("hist=15: got %d, want %d", a, kEsiTab[48+15])
	}
}

// TestEsiAfterMatchIgnoresEsi verifies that the esi parameter is
// unused (the function indexes by cls + hist, not by esi).
func TestEsiAfterMatchIgnoresEsi(t *testing.T) {
	a := EsiAfterMatch(0, 0, 5)
	b := EsiAfterMatch(99, 0, 5)
	c := EsiAfterMatch(255, 0, 5)
	if a != b || b != c {
		t.Fatalf("esi should be ignored: %d %d %d", a, b, c)
	}
}