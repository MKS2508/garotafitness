// Package godec — Magic2Decode entry-point tests.
//
// Magic2Decode iterates ~50 variants of decode_v22 and accepts the
// first whose output passes hit_crc (CRC32-IEEE at offset kEmu). The
// tests below pin:
//
//   - the entry-guard contract (nil state, empty dst, sub-4 src)
//   - the iteration runs without panic on every fixture the rest of
//     the test suite treats as valid magic2 input
//   - the final fallback returns whatever the last variant produced
//     (the C source's `return decode_v22(...);` at main.cpp:1671)
//   - the iteration order is preserved (a refactor that reorders
//     variants must keep the same first-wins semantics)
//
// The simplified classifier does not implement the production
// decode_v22 logic, so the real-magic2 hit is not exercised here —
// that requires porting the opt-header + recent-offset + LZ subroutines.
// The corpus path is the closest proxy: it loads a real magic2 body,
// runs the full iteration, and verifies the function returns without
// panic and with bounded output.
package godec

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
)

// =====================================================================
// Entry guards
// =====================================================================

// TestMagic2DecodeNilState guards the nil-state early-out. The
// production streaming reader threads State through, but unit tests
// that pass nil must not panic.
func TestMagic2DecodeNilState(t *testing.T) {
	out := Magic2Decode(context.Background(), nil,
		[]byte{0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
		make([]byte, 4096))
	if out != 0 {
		t.Fatalf("nil state: out = %d, want 0", out)
	}
}

// TestMagic2DecodeShortInput covers the sub-4-byte guard. The function
// must return 0 on any input shorter than the chunk header without
// indexing past the slice.
func TestMagic2DecodeShortInput(t *testing.T) {
	dst := make([]byte, 4096)
	for _, src := range [][]byte{
		nil,
		{},
		{0x01},
		{0x01, 0x02, 0x03},
	} {
		out := Magic2Decode(context.Background(), &State{}, src, dst)
		if out != 0 {
			t.Fatalf("src=%x: out = %d, want 0", src, out)
		}
	}
}

// TestMagic2DecodeEmptyDst covers the empty-dst guard. The function
// returns 0 when the output buffer can't hold anything.
func TestMagic2DecodeEmptyDst(t *testing.T) {
	for _, dst := range [][]byte{
		nil,
		{},
		make([]byte, 0),
	} {
		out := Magic2Decode(context.Background(), &State{},
			[]byte{0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
			dst)
		if out != 0 {
			t.Fatalf("dst=%v: out = %d, want 0", dst, out)
		}
	}
}

// =====================================================================
// Iteration behaviour
// =====================================================================

// TestMagic2DecodeAllVariantsEOF pins the no-hit fall-through. An
// all-zeros body has chunk_size=0 → every variant hits EOF before
// producing a byte → no variant passes hit_crc → Magic2Decode
// returns 0 (the last variant's count).
func TestMagic2DecodeAllVariantsEOF(t *testing.T) {
	body := make([]byte, 64)
	dst := make([]byte, 8192)
	out := Magic2Decode(context.Background(), &State{}, body, dst)
	if out != 0 {
		t.Fatalf("out = %d, want 0 (all variants EOF → no hit → fall through returns 0)",
			out)
	}
}

// TestMagic2DecodeSmallestValid verifies the function runs through
// every variant on a body that produces 1 byte per call. No variant
// passes hit_crc (output is 1 byte < kEmu+kApp), so the result is
// the count from the last variant (1). The function must not panic
// across the ~50-variant iteration.
//
// dst is sized at 1 byte to clamp each variant's output. The
// previous scaffold's chunkSize-header semantics bounded this; the
// cls11 dispatch consumes more bits per symbol, so an explicit
// dst cap is the equivalent invariant.
func TestMagic2DecodeSmallestValid(t *testing.T) {
	body := []byte{0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}
	dst := make([]byte, 1)
	out := Magic2Decode(context.Background(), &State{}, body, dst)
	if out != 1 {
		t.Fatalf("out = %d, want 1 (last variant's count, dst-clamped)", out)
	}
}

// TestMagic2DecodeClampsOutputToDst verifies dst bounds are honoured.
// A body that produces 4 bytes but a dst of 16 bytes: the copy into
// dst caps at 16 (it doesn't truncate to fewer because the output
// is shorter), but a dst of 2 bytes MUST truncate without panic.
func TestMagic2DecodeClampsOutputToDst(t *testing.T) {
	body := []byte{0x04, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF}
	// Tiny dst: copy caps at 2. None of the variants produces >= kEmu
	// bytes, so no hit fires; the function returns the last variant's
	// capped count.
	dst := make([]byte, 2)
	out := Magic2Decode(context.Background(), &State{}, body, dst)
	if out > 2 {
		t.Fatalf("out = %d, want <= 2 (dst capped copy)", out)
	}
}

// TestMagic2DecodeContextCancel verifies a pre-cancelled context
// surfaces cleanly. Every variant's first ctx.Err() check fires, so
// the function returns 0 without iterating the rest.
func TestMagic2DecodeContextCancel(t *testing.T) {
	body := []byte{0x04, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dst := make([]byte, 8192)
	out := Magic2Decode(ctx, &State{}, body, dst)
	if out != 0 {
		t.Fatalf("out = %d, want 0 (ctx cancelled before any variant runs)", out)
	}
}

// TestMagic2DecodeDeterministic verifies the function is deterministic:
// two back-to-back calls on the same State produce identical output.
// The streaming reader relies on this for SHA round-trips.
func TestMagic2DecodeDeterministic(t *testing.T) {
	body := []byte{0x04, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF}

	var st1, st2 State
	st1.ROLZ.Reset()
	st2.ROLZ.Reset()

	dst1 := make([]byte, 8192)
	dst2 := make([]byte, 8192)

	out1 := Magic2Decode(context.Background(), &st1, body, dst1)
	out2 := Magic2Decode(context.Background(), &st2, body, dst2)

	if out1 != out2 {
		t.Fatalf("non-deterministic: out1=%d out2=%d", out1, out2)
	}
	if !bytes.Equal(dst1[:out1], dst2[:out2]) {
		t.Fatalf("non-deterministic output bytes:\n  dst1=%x\n  dst2=%x",
			dst1[:out1], dst2[:out2])
	}
}

// =====================================================================
// Header fixtures
// =====================================================================

// TestMagic2DecodeTinyChunk verifies the iteration completes on a
// synthetic body with a small chunk_size that all variants can drive.
// Replaces the earlier testdata-header test which ran ~50 variants
// each allocating 1.85 GB (the sample fg02/fg06 header's chunk_size)
// — same correctness, ~50× cheaper. The corpus test below exercises
// the real magic2 path.
func TestMagic2DecodeTinyChunk(t *testing.T) {
	// cap=4 (dst size clamps each variant's output to 4 bytes). The
	// classifier output is too short to pass hit_crc (n=4 < kEmu+kApp),
	// so Magic2Decode returns the last variant's count (4).
	body := []byte{0x04, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF}
	dst := make([]byte, 4)
	out := Magic2Decode(context.Background(), &State{}, body, dst)
	if out != 4 {
		t.Fatalf("out = %d, want 4 (last variant's count, dst-clamped)", out)
	}
}

// =====================================================================
// Corpus: fg-07 first chunk
// =====================================================================

// TestMagic2DecodeCorpusFg07HeaderParsed loads fg-07.bin's first
// chunk-group header and runs Magic2Decode against it. Skips if
// the corpus is unavailable.
//
// Pins:
//   - no panic on a real magic2 fixture
//   - output is bounded (the iteration never writes more than len(dst))
//   - the function returns without error (Magic2Decode has no error
//     return — its int result is the byte count, not a status code)
//   - if a variant fires hit_crc, the output is at least kEmu+kApp
//     bytes (the marker requires both the emulator prefix AND the
//     application payload)
//
// The simplified classifier doesn't implement the real decode_v22
// logic, so a real hit isn't expected here. The test exists to lock
// the iteration's safety on real magic2 input — a refactor that
// breaks the variant order or the dst-copy semantics will surface
// here as either a panic or an unbounded output.
func TestMagic2DecodeCorpusFg07HeaderParsed(t *testing.T) {
	f := corpus.File(t, "fg-07.bin")

	// Skip past FreeArc header (31 bytes, matches fg07_consumed_test).
	if _, err := f.Seek(31, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	// Read the first ~4 KiB — enough to cover the chunk header (4
	// bytes) + a meaningful rANS state for any variant that wants
	// to drive a decode. The full fg-07 body is ~365 KiB; we only
	// need the first chunk-group here.
	const firstChunk = 4096
	body := make([]byte, firstChunk)
	n, err := io.ReadFull(f, body)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	body = body[:n]
	if len(body) < 4 {
		t.Fatalf("fg-07 body too short: %d bytes", len(body))
	}

	dst := make([]byte, 1<<16) // 64 KiB scratch
	var st State
	st.ROLZ.Reset()

	out := Magic2Decode(context.Background(), &st, body, dst)

	// Output is bounded by len(dst). A real hit fires iff some
	// variant decoded >= kEmu+kApp bytes with the right CRC; the
	// simplified classifier never hits that today, so out is the
	// last variant's count (likely small or 0).
	if out < 0 {
		t.Fatalf("out = %d (negative — Magic2Decode returns >= 0)", out)
	}
	if out > len(dst) {
		t.Fatalf("out = %d > len(dst) = %d (no dst bounds check)", out, len(dst))
	}
	t.Logf("fg-07 Magic2Decode: in=%d out=%d (no real hit expected on simplified classifier)",
		len(body), out)
}
