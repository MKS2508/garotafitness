// Package godec — LZ window + ROLZ hash chain primitives.
//
// The cls-magic2 x64 PE keeps two coupled structures per decoded stream:
// the LZ history (a 16 MiB ring buffer at obj+0x1c/0x1e with a 24-bit
// cursor at obj+0x58 — param_1[0x16] in FUN_140029700 / FUN_140037790)
// and the ROLZ hash chain (gRolz[256][2048] at obj+0xc90 with cursors
// at obj+0x88). This file ports both into Go as unit-testable primitives
// with the same semantics the PE executes.
//
// The PE actually allocates two banks of 16 MiB (param_1[0x12a] and
// param_1[300]) and copies the rotation tail from one to the other when
// the cursor wraps past 0xFFFFFF. For unit-level work on MatchCopy and
// LiteralCopy we model the simpler single-bank abstraction and let
// MatchCopy mask every position through kRingMask — the byte-at-a-time
// in-place copy that FUN_140029700's inner loop runs self-replicates via
// src/dst overlap, which is exactly what masking gives us.
package godec

// kRingSize is the magic2 ring buffer size: 1<<24 = 16 MiB. Mirrors the
// PE's 24-bit cursor mask (param_1[0x16] & 0xffffff in FUN_140029700,
// line 152/159) and the rotation thresholds 0x1000000 / 0xFFFFFF that
// appear throughout FUN_140029700 and FUN_140037790.
const kRingSize = 1 << 24

// kRingMask is the position mask used to wrap positions into [0, kRingSize).
const kRingMask = kRingSize - 1

// RolzCap is the per-context hash chain cap. Mirrors kRolzCap = 2048 in
// the guest C++ reconstruction (main.cpp:603) and the gRolz[256][2048]
// layout the cls-magic2 PE keeps at obj+0xc90.
const RolzCap = 2048

// RingBuffer is the magic2 decode window — a single 16 MiB byte slice
// with a 24-bit cursor and the current literal byte slot. The PE keeps
// Pos in param_1[0x16] (uint, masked to 24 bits) and the literal byte
// in param_1[0x20] / param_1[0x30b] depending on the LZ path; the Slot
// field here is the Go-visible mirror of that literal-byte staging slot.
//
// Slot is exported so the caller can pre-load it from the rANS state
// before invoking LiteralCopy — the PE itself interleaves the byte read
// from rANS with the ring buffer write, but in Go we want the function
// signature LiteralCopy(buf, dst int) to be literal.
type RingBuffer struct {
	Buf  [kRingSize]byte // 16 MiB sliding window
	Pos  int             // 24-bit cursor; advances past every emitted byte
	Slot byte            // current literal byte (staging slot)
}

// MatchCopy copies `length` bytes from position `ref` in the ring buffer
// into the slot starting at position `dst`. Each source byte is read
// through kRingMask, so a match that crosses the 16 MiB boundary
// self-replicates via the in-place src/dst overlap the way the PE does
// (the literal loop in FUN_140029700 around line 686 is a
// byte-at-a-time copy that the SIMD path collapses into movdqu; the
// semantics are the same).
//
// Mirrors the inner loop at FUN_140029700:684-690 in the cls-magic2 x64
// PE:
//
//	pbVar32 = (byte *)(uVar36 + local_60);          // dst in ring bank
//	lVar27  = (~local_120 + uVar36 & 0xffffff) - ... // offset to ref
//	do {
//	    *pbVar32 = pbVar32[lVar27 + lVar42];        // read+write 1 byte
//	    pbVar32++;
//	} while (pbVar32 < pbVar3);                     // until length reached
//
// dst and ref need not be ordered — the byte-at-a-time forward copy is
// correct for any (dst, ref, length) combination because each iteration
// reads its source byte before writing its destination byte (and the
// masking keeps every position inside the same buffer).
func (r *RingBuffer) MatchCopy(dst, ref, length int) {
	for i := 0; i < length; i++ {
		r.Buf[(dst+i)&kRingMask] = r.Buf[(ref+i)&kRingMask]
	}
}

// LiteralCopy writes the staging byte (Slot) into the ring buffer at
// `dst` and advances the cursor by one position. The PE reads the
// literal byte from the rANS bitstream before invoking the equivalent
// in-image store (`dst[n] = b;` at main.cpp:813 / 1143 / 1185 / 1224 /
// 1262 / 1301); the caller is responsible for pre-loading Slot from the
// rANS state before calling LiteralCopy. Keeping the byte in the
// RingBuffer's Slot field lets LiteralCopy match the task signature
// exactly while leaving the byte source explicit at the call site.
//
// The cursor advance is the load-bearing detail: a single 24-bit
// position counter that wraps at kRingSize. The PE keeps the same
// counter at param_1[0x16] and masks to 24 bits on every store.
func (r *RingBuffer) LiteralCopy(dst int) {
	r.Buf[dst&kRingMask] = r.Slot
	r.Pos++
}

// HashChain is the gRolz[256][2048] structure from main.cpp:606 — 256
// context buckets, each a circular buffer of recent match positions
// (length up to 2048). Ctx 0 is a valid bucket (the cls-magic2 PE keeps
// it populated from the very first byte, where "previous byte" is just
// the byte at the start of the ring).
type HashChain struct {
	List [256][RolzCap]uint32 // 256 ctx * 2048 slots * 4 B = 2 MiB
	Cur  [256]uint32          // next slot to write into each ctx
}

// Reset clears all 256 ctx buckets and rewinds every cursor to 0.
// Mirrors the rolz_reset() helper in main.cpp:613-616 and the
// cls-magic2 PE reset that zeroes the gRolz block at stream start
// (the PE allocates the block with a single memset before the first
// decode_v22 call).
func (h *HashChain) Reset() {
	for c := range h.List {
		for i := range h.List[c] {
			h.List[c][i] = 0
		}
		h.Cur[c] = 0
	}
}

// Push records `pos` into the ctx bucket, advancing the cursor with
// wrap at RolzCap. Mirrors rolz_push (main.cpp:618-625) and the
// cls-magic2 PE store at the cursor-th slot of gRolz[ctx].
//
// uint32 truncation matches the C++ cast `(uint32_t)pos`; it preserves
// correct wrap behaviour when the 24-bit position counter rolls past
// 0xFFFFFF (the high byte of pos, which carries the bank flag in the
// PE's wider 32-bit position field, is dropped — for hash chain
// indexing the bank flag is irrelevant).
func (h *HashChain) Push(ctx int, pos int) {
	ctx &= 255
	c := h.Cur[ctx]
	h.List[ctx][c] = uint32(pos)
	c++
	if c >= RolzCap {
		c = 0
	}
	h.Cur[ctx] = c
}

// Lookup reads the slot at distance `idx` behind the cursor for ctx and
// returns the stored position. Mirrors rolz_lookup (main.cpp:627-640)
// which the PE inlines; the slot arithmetic is
//
//	slot = cur + ~idx        // == cur - idx - 1
//	if slot < 0:  slot += RolzCap
//
// with the negative-wrap correction (the cls-magic2 PE keeps both the
// `slot + RolzCap` and the `slot >= RolzCap → slot %= RolzCap` guards
// but the second guard is dead under the first — only the negative
// branch is reachable from the inlined use sites).
//
// idx 0 means "most recent push for ctx"; idx 1 the next-most-recent;
// the 2047-th oldest is at idx = 2047 (the cursor is always the slot
// AFTER the most recent push, so the most-recent push is at
// cur-1, not cur).
//
// Returns 0 when ctx has never been pushed (the cls-magic2 PE also
// returns 0 in that case via the `cur < 1 → return 1` early-out
// followed by an unconditional load from a slot that rolz_reset
// cleared to 0).
func (h *HashChain) Lookup(ctx int, idx int) uint32 {
	ctx &= 255
	cur := h.Cur[ctx]
	if cur < 1 {
		return 0
	}
	slot := int(cur) + ^idx
	if slot < 0 {
		slot += RolzCap
	}
	if slot >= RolzCap {
		return 0
	}
	return h.List[ctx][slot]
}

// LookupDistance mirrors rolz_lookup (main.cpp:627-640): returns the match
// distance `n - pos` for the position stored at idx-behind-cursor in ctx,
// floored at 1. An empty ctx returns 1 — the cls-magic2 PE has the same
// early-out (`if cur < 1 return 1;` in main.cpp:631-632).
//
// Mirrors main.cpp:627-640 verbatim:
//
//	slot = cur + ~idx        // == cur - idx - 1
//	if slot < 0:  slot += RolzCap
//	if slot >= RolzCap:  slot %= RolzCap
//	d = n - pos
//	if d < 1: d = 1
//	return d
//
// The PE keeps the modulo guard but the negative-wrap correction already
// constrained slot to (-RolzCap, RolzCap), so the second guard is dead —
// only the negative branch is reachable from inlined use sites.
//
// The C version returns `d` (the distance, not the position) because the
// inlined LZ loop at main.cpp:1474 uses it as the offset fed into
// decode_off. Lookup above returns the raw position for unit-level work;
// LookupDistance returns the LZ-loop-shaped distance for the call sites.
func (h *HashChain) LookupDistance(ctx int, idx int, n int) int {
	ctx &= 255
	cur := h.Cur[ctx]
	if cur < 1 {
		return 1
	}
	slot := int(cur) + ^idx
	if slot < 0 {
		slot += RolzCap
	}
	if slot >= RolzCap {
		slot %= RolzCap
	}
	pos := int(h.List[ctx][slot])
	d := n - pos
	if d < 1 {
		d = 1
	}
	return d
}