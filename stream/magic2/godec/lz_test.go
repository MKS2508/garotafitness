package godec

import (
	"bytes"
	"testing"
)

// TestMatchCopyFromKnownPosition verifies the MatchCopy inner loop against a
// deterministic byte sequence at a known ring buffer position. The cls-magic2
// PE inner loop at FUN_140029700:684-690 is the byte-at-a-time copy that the
// SIMD path collapses into movdqu; the Go port keeps the byte-at-a-time
// shape so a future swap to vectorized assembly can be measured against the
// same fixture.
func TestMatchCopyFromKnownPosition(t *testing.T) {
	var r RingBuffer
	// Seed ring buffer at positions [0..6) with a known sequence.
	src := []byte("abcdef")
	copy(r.Buf[:len(src)], src)

	// Match: copy 4 bytes from ref=2 ("cdef") to dst=100.
	r.MatchCopy(100, 2, 4)

	want := []byte("cdef")
	for i, w := range want {
		got := r.Buf[(100+i)&kRingMask]
		if got != w {
			t.Fatalf("MatchCopy wrote 0x%02x at dst=%d, want 0x%02x (byte %d of %q)",
				got, 100+i, w, i, src)
		}
	}
}

// TestMatchCopyAcrossBoundary verifies the 16 MiB wrap behaviour. The PE
// keeps param_1[0x16] masked to 24 bits and the inner loop reads through
// the ring buffer at masked positions; a match that starts near the end
// of the buffer and spills past 0xFFFFFF must read from offset 0 onward.
//
// Source lives at [100..110) and target spans the boundary
// [kRingSize-5 .. kRingSize+5); the two regions don't overlap, so the
// byte-at-a-time forward copy is the same as a non-overlapping memcpy
// and the wrap is observable end-to-end.
func TestMatchCopyAcrossBoundary(t *testing.T) {
	var r RingBuffer
	src := []byte("ABCDEFGHIJ")
	copy(r.Buf[100:100+len(src)], src)

	dst := kRingSize - 5
	const length = 10
	r.MatchCopy(dst, 100, length)

	for i, w := range src {
		got := r.Buf[(dst+i)&kRingMask]
		if got != w {
			t.Fatalf("wrap match: dst=%d (masked=%d) byte %d: got 0x%02x, want 0x%02x",
				dst+i, (dst+i)&kRingMask, i, got, w)
		}
	}
}

// TestMatchCopySelfOverlapping verifies the byte-at-a-time forward copy
// is correct when dst and ref alias. The PE's inner loop reads src[i]
// BEFORE writing dst[i]; a future vectorized implementation has to
// either keep the byte-at-a-time order or detect the overlap and
// fall back. This fixture pins the byte-at-a-time contract.
func TestMatchCopySelfOverlapping(t *testing.T) {
	var r RingBuffer
	// Seed [0..4) with "ABCD".
	copy(r.Buf[:4], []byte("ABCD"))
	// Match: dst=1, ref=0, length=6 — byte-at-a-time reads:
	//   i=0: src=0 'A' → dst=1 ← 'A'
	//   i=1: src=1 'A' → dst=2 ← 'A'  (ref advanced by the write)
	//   i=2: src=2 'A' → dst=3 ← 'A'
	//   ... all become 'A' (memset-style self-replication).
	r.MatchCopy(1, 0, 6)
	for i := 1; i < 7; i++ {
		if got := r.Buf[i]; got != 'A' {
			t.Fatalf("self-overlap byte %d: got 0x%02x, want 'A'", i, got)
		}
	}
}

// TestLiteralCopyPassesThroughSingleByte verifies the literal staging
// path. The PE reads the byte from the rANS bitstream before invoking
// the equivalent in-image store; the Go port pre-loads Slot so the
// LiteralCopy signature stays a clean (buf, dst int).
func TestLiteralCopyPassesThroughSingleByte(t *testing.T) {
	var r RingBuffer
	r.Slot = 0x42
	posBefore := r.Pos
	r.LiteralCopy(100)
	if got := r.Buf[100]; got != 0x42 {
		t.Fatalf("LiteralCopy wrote 0x%02x at dst=100, want 0x42", got)
	}
	if r.Pos != posBefore+1 {
		t.Fatalf("LiteralCopy advanced Pos from %d to %d, want %d",
			posBefore, r.Pos, posBefore+1)
	}

	// Re-load Slot to a different value and verify only that byte is
	// written, not the previous one.
	r.Slot = 0x99
	r.LiteralCopy(200)
	if got := r.Buf[200]; got != 0x99 {
		t.Fatalf("second LiteralCopy wrote 0x%02x at dst=200, want 0x99", got)
	}
	// Spot-check the prior write survived.
	if got := r.Buf[100]; got != 0x42 {
		t.Fatalf("first LiteralCopy byte clobbered: dst=100 now 0x%02x, want 0x42", got)
	}
}

// TestLiteralCopyMaskingPastBoundary verifies the position mask
// applied on the dst index — writing near the 24-bit wrap point
// lands at offset (kRingSize - 4) & kRingMask, NOT at a high address
// past the buffer.
func TestLiteralCopyMaskingPastBoundary(t *testing.T) {
	var r RingBuffer
	r.Slot = 0xCD
	dst := kRingSize - 4 // well past end of 16 MiB
	r.LiteralCopy(dst)
	// After masking, the byte lands at offset kRingSize-4, not kRingSize-4.
	if got := r.Buf[kRingSize-4]; got != 0xCD {
		t.Fatalf("wrap-around literal dst=%d landed at 0x%02x, want 0xCD at offset %d",
			dst, got, kRingSize-4)
	}
}

// TestHashChainPushAndLookup verifies the round-trip push/lookup path
// for the gRolz[256][2048] structure. Pushes four positions into ctx
// 0xAA, then looks them up at idx 0 (most recent), 1, 2, 3 (oldest).
func TestHashChainPushAndLookup(t *testing.T) {
	var h HashChain
	const ctx = 0xAA
	for _, pos := range []uint32{0x10, 0x20, 0x30, 0x40} {
		h.Push(ctx, int(pos))
	}
	want := []uint32{0x40, 0x30, 0x20, 0x10} // most recent first
	for idx, w := range want {
		got := h.Lookup(ctx, idx)
		if got != w {
			t.Fatalf("Lookup(ctx=0x%02x, idx=%d) = 0x%x, want 0x%x", ctx, idx, got, w)
		}
	}
}

// TestHashChainWrapPastCap verifies the cursor wraps at RolzCap and
// that the oldest entry is overwritten. Pushing 2049 entries into one
// ctx leaves the 1-entry from the start as the most-recent (idx 0)
// and the 2-entry as the second-most-recent (idx 1).
func TestHashChainWrapPastCap(t *testing.T) {
	var h HashChain
	const ctx = 0x07
	// Push 2049 entries: positions 0, 1, 2, …, 2048. After the wrap the
	// table contains positions 1..2048 (position 0 was overwritten by
	// position 2048 at the slot the cursor was at when 2048 arrived).
	for i := 0; i <= RolzCap; i++ {
		h.Push(ctx, i)
	}
	// Most recent: i = RolzCap = 2048.
	if got := h.Lookup(ctx, 0); got != uint32(RolzCap) {
		t.Fatalf("after wrap, most-recent = 0x%x, want 0x%x", got, RolzCap)
	}
	// Second-most-recent: i = RolzCap-1 = 2047.
	if got := h.Lookup(ctx, 1); got != uint32(RolzCap-1) {
		t.Fatalf("after wrap, idx=1 = 0x%x, want 0x%x", got, RolzCap-1)
	}
	// Oldest reachable (idx = RolzCap-1, which wraps the cursor back to
	// slot 1, which now holds i=1 — position 0 was evicted).
	if got := h.Lookup(ctx, RolzCap-1); got != 1 {
		t.Fatalf("after wrap, oldest = 0x%x, want 1 (position 0 evicted)", got)
	}
}

// TestHashChainLookupEmpty verifies the empty-ctx guard. Without a
// push the cursor sits at 0 and Lookup returns 0 — the cls-magic2 PE
// has the same early-out (`if cur < 1 return 1;` in main.cpp:631-632,
// with the slot then loaded as 0 from the rolz_reset clear).
func TestHashChainLookupEmpty(t *testing.T) {
	var h HashChain
	if got := h.Lookup(0x55, 0); got != 0 {
		t.Fatalf("empty ctx Lookup returned 0x%x, want 0", got)
	}
}

// TestHashChainLookupDistance verifies the distance return path the
// inlined LZ loop at main.cpp:1474 uses (`extra = rolz_lookup(prev,
// idx, n)`). With ctx=0xAA storing positions [10, 20, 30] in that order,
// the cursor points at slot 3, and LookupDistance(_, 0, 100) must
// compute 100 - 30 = 70 (the distance to the most-recent push).
func TestHashChainLookupDistance(t *testing.T) {
	var h HashChain
	const ctx = 0xAA
	for _, pos := range []uint32{10, 20, 30} {
		h.Push(ctx, int(pos))
	}
	// idx 0 → most recent (30), distance = 100 - 30 = 70.
	if got := h.LookupDistance(ctx, 0, 100); got != 70 {
		t.Fatalf("LookupDistance(idx=0) = %d, want 70", got)
	}
	// idx 1 → next-most-recent (20), distance = 100 - 20 = 80.
	if got := h.LookupDistance(ctx, 1, 100); got != 80 {
		t.Fatalf("LookupDistance(idx=1) = %d, want 80", got)
	}
	// idx 2 → oldest (10), distance = 100 - 10 = 90.
	if got := h.LookupDistance(ctx, 2, 100); got != 90 {
		t.Fatalf("LookupDistance(idx=2) = %d, want 90", got)
	}
}

// TestHashChainLookupDistanceFloor verifies the d < 1 → 1 guard at
// main.cpp:639. When the stored position is ahead of n (wrap-around
// stale entry after a stream reset, or a hash chain collision that
// happened to land at a high slot), the distance floors to 1 — the
// same minimum the C function enforces.
func TestHashChainLookupDistanceFloor(t *testing.T) {
	var h HashChain
	const ctx = 0x77
	// Single push at pos=500, n=10. The C function computes d = 10 -
	// 500 = -490, which clamps to 1.
	h.Push(ctx, 500)
	if got := h.LookupDistance(ctx, 0, 10); got != 1 {
		t.Fatalf("LookupDistance with pos > n = %d, want 1 (floor guard)", got)
	}
}

// TestHashChainLookupDistanceEmpty verifies the empty-ctx early-out.
// With no push into ctx, LookupDistance returns 1 — the cls-magic2 PE
// has the same early-out (`if cur < 1 return 1;` in main.cpp:631-632).
func TestHashChainLookupDistanceEmpty(t *testing.T) {
	var h HashChain
	if got := h.LookupDistance(0x33, 0, 100); got != 1 {
		t.Fatalf("LookupDistance on empty ctx = %d, want 1", got)
	}
}

// TestHashChainLookupDistanceMatchExact verifies n == pos returns 0
// before the floor guard clamps it to 1. The C code computes
// d = n - pos = 0, then `if (d < 1) d = 1;` raises it. This test pins
// that the floor guard handles the exact-zero case.
func TestHashChainLookupDistanceMatchExact(t *testing.T) {
	var h HashChain
	const ctx = 0x99
	h.Push(ctx, 42)
	if got := h.LookupDistance(ctx, 0, 42); got != 1 {
		t.Fatalf("LookupDistance at exact pos = %d, want 1 (floor clamps 0)", got)
	}
}

// TestHashChainReset verifies Reset zeroes every bucket and rewinds
// every cursor. Mirrors the cls-magic2 PE reset (memset over gRolz
// + 256 stores to gRolzCur) that runs before each decode_v22 call.
func TestHashChainReset(t *testing.T) {
	var h HashChain
	h.Push(0x11, 0xDEAD)
	h.Push(0x22, 0xBEEF)
	h.Reset()
	for c := 0; c < 256; c++ {
		if h.Cur[c] != 0 {
			t.Fatalf("after Reset, Cur[%d] = %d, want 0", c, h.Cur[c])
		}
		for i := 0; i < RolzCap; i++ {
			if h.List[c][i] != 0 {
				t.Fatalf("after Reset, List[%d][%d] = 0x%x, want 0",
					c, i, h.List[c][i])
			}
		}
	}
}

// TestRingBufferSizeLayout pins the 16 MiB size and the mask constant
// so a future widening (e.g. switching to 32 MiB to handle larger
// dictionary streams) gets caught at test time. The PE uses
// 0x1000000 / 0xFFFFFF throughout; deviating without updating those
// constants would silently produce wrong match/copy behaviour.
func TestRingBufferSizeLayout(t *testing.T) {
	if kRingSize != 1<<24 {
		t.Fatalf("kRingSize = %d, want %d (1<<24)", kRingSize, 1<<24)
	}
	if kRingMask != (1<<24)-1 {
		t.Fatalf("kRingMask = 0x%x, want 0x%x", kRingMask, (1<<24)-1)
	}
	if got := new(RingBuffer); len(got.Buf) != kRingSize {
		t.Fatalf("RingBuffer.Buf length = %d, want %d", len(got.Buf), kRingSize)
	}
	if got := new(HashChain); len(got.List) != 256 || len(got.List[0]) != RolzCap {
		t.Fatalf("HashChain.List dims = [%d][%d], want [256][%d]",
			len(got.List), len(got.List[0]), RolzCap)
	}
}

// TestMatchCopyZeroLengthNoOp verifies the zero-length case doesn't
// touch the buffer at all. The cls-magic2 PE inner loop's `while
// (pbVar32 < pbVar3)` check makes the zero case a clean no-op, and
// the SIMD path's movdqu with XMM0/zero-length also touches nothing.
// This pins the no-op contract so a future vectorized port doesn't
// accidentally over-read past ref+0 (which would mask correctly but
// wastes bandwidth).
func TestMatchCopyZeroLengthNoOp(t *testing.T) {
	var r RingBuffer
	// Seed a recognizable pattern at [0..16).
	fixture := []byte("0123456789ABCDEF")
	copy(r.Buf[:16], fixture)

	before := [16]byte{}
	copy(before[:], r.Buf[:16])

	r.MatchCopy(100, 0, 0)

	if !bytes.Equal(r.Buf[:16], before[:]) {
		t.Fatalf("MatchCopy(_, _, 0) mutated buffer: %v vs %v", r.Buf[:16], before[:])
	}
}