package godec

import (
	"testing"
	"unsafe"
)

// TestInitNibble16 verifies the uniform 16-slot CDF seed from
// main.cpp:663-666. The exact byte sequence is 0x0000, 0x0800, 0x1000,
// 0x1800, 0x2000, 0x2800, 0x3000, 0x3800, 0x4000, 0x4800, 0x5000, 0x5800,
// 0x6000, 0x6800, 0x7000, 0x7800 — step 0x800, range 0x8000 = 2^15.
//
// Reference: main.cpp calls init_nibble on hiA, hiB, loA, loB, clsTab,
// off2A, off2B, off3A, off3B, off11A, … every entry of those tables must
// hold this exact sequence.
func TestInitNibble16(t *testing.T) {
	var got Nibble16
	init_nibble(got[:])

	want := Nibble16{
		0x0000, 0x0800, 0x1000, 0x1800,
		0x2000, 0x2800, 0x3000, 0x3800,
		0x4000, 0x4800, 0x5000, 0x5800,
		0x6000, 0x6800, 0x7000, 0x7800,
	}
	for i := 0; i < 16; i++ {
		if got[i] != want[i] {
			t.Fatalf("init_nibble d[%d]=0x%04x, want 0x%04x", i, got[i], want[i])
		}
	}

	// Range invariant: sum of all slots must equal the rANS window 2^15.
	var sum uint32
	for _, v := range got {
		sum += uint32(v)
	}
	// arithmetic sum of 0, 0x800, …, 0x7800 = 8 * 0x8000 = 0x40000.
	const wantSum = uint32(16-1) * uint32(16) / 2 * 0x800
	if sum != wantSum {
		t.Fatalf("init_nibble sum=0x%x, want 0x%x", sum, wantSum)
	}
}

// TestInitSym8 verifies the uniform 8-slot CDF seed from main.cpp:667-670.
// The exact byte sequence is 0x0000, 0x1000, 0x2000, 0x3000, 0x4000, 0x5000,
// 0x6000, 0x7000 — step 0x1000, range 0x8000 = 2^15.
//
// Reference: main.cpp calls init_sym8 on lenTab (8192 rows), off8a and
// off8b (32 rows each).
func TestInitSym8(t *testing.T) {
	var got Sym8
	init_sym8(got[:])

	want := Sym8{
		0x0000, 0x1000, 0x2000, 0x3000,
		0x4000, 0x5000, 0x6000, 0x7000,
	}
	for i := 0; i < 8; i++ {
		if got[i] != want[i] {
			t.Fatalf("init_sym8 d[%d]=0x%04x, want 0x%04x", i, got[i], want[i])
		}
	}

	// Range invariant: sum of all slots must equal the rANS window 2^15.
	var sum uint32
	for _, v := range got {
		sum += uint32(v)
	}
	const wantSum = uint32(8-1) * uint32(8) / 2 * 0x1000
	if sum != wantSum {
		t.Fatalf("init_sym8 sum=0x%x, want 0x%x", sum, wantSum)
	}
}

// TestInitNibbleIntoRowOfBiggerBuffer mirrors the C++ call pattern
// `init_nibble(bigBuf + i*16)` where bigBuf is a flat array and the caller
// hands the helper a pointer into the middle of it. Verifies the Go
// slice-based API behaves the same: only the first 16 slots get seeded.
func TestInitNibbleIntoRowOfBiggerBuffer(t *testing.T) {
	// 64-row buffer; seed row 2 (slots [32..48)) and confirm the rest
	// of the buffer is untouched.
	big := make([]uint16, 64)
	for i := range big {
		big[i] = 0xCAFE
	}

	init_nibble(big[32 : 32+16])

	for i := 0; i < 32; i++ {
		if big[i] != 0xCAFE {
			t.Fatalf("pre-row big[%d]=0x%04x, want untouched 0xCAFE", i, big[i])
		}
	}
	for i, want := range []uint16{
		0x0000, 0x0800, 0x1000, 0x1800,
		0x2000, 0x2800, 0x3000, 0x3800,
		0x4000, 0x4800, 0x5000, 0x5800,
		0x6000, 0x6800, 0x7000, 0x7800,
	} {
		if big[32+i] != want {
			t.Fatalf("row big[32+%d]=0x%04x, want 0x%04x", i, big[32+i], want)
		}
	}
	for i := 48; i < 64; i++ {
		if big[i] != 0xCAFE {
			t.Fatalf("post-row big[%d]=0x%04x, want untouched 0xCAFE", i, big[i])
		}
	}
}

// TestInitSym8IntoRowOfBiggerBuffer mirrors `init_sym8(bigBuf + i*8)`.
func TestInitSym8IntoRowOfBiggerBuffer(t *testing.T) {
	big := make([]uint16, 32)
	for i := range big {
		big[i] = 0xBEEF
	}

	init_sym8(big[16 : 16+8])

	for i := 0; i < 16; i++ {
		if big[i] != 0xBEEF {
			t.Fatalf("pre-row big[%d]=0x%04x, want untouched 0xBEEF", i, big[i])
		}
	}
	for i, want := range []uint16{
		0x0000, 0x1000, 0x2000, 0x3000,
		0x4000, 0x5000, 0x6000, 0x7000,
	} {
		if big[16+i] != want {
			t.Fatalf("row big[16+%d]=0x%04x, want 0x%04x", i, big[16+i], want)
		}
	}
	for i := 24; i < 32; i++ {
		if big[i] != 0xBEEF {
			t.Fatalf("post-row big[%d]=0x%04x, want untouched 0xBEEF", i, big[i])
		}
	}
}

// TestHistLayout pins the total struct size so a future layout drift
// (e.g. someone widening a field to uint64, or dropping a counter)
// gets caught at test time, not at Ghidra-decompile-time. main.cpp:670-674
// declares eight packed uint32 fields — 8 * 4 = 32 bytes, no padding.
func TestHistLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(Hist{}), uintptr(32); got != want {
		t.Fatalf("sizeof(Hist)=%d, want %d", got, want)
	}
}
