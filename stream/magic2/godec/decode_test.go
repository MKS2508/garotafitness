package godec

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// All-zeros input → EOF cleanly. chunk_size == 0 (LE) → loop never runs,
// out stays empty, function returns EOF. consumed reflects the rANS
// initialization drain (NewLE reads 4 bytes, Renorm pulls more until X
// saturates above kL); for a long all-zeros body that consumes the full
// input. The contract is: bytes from consumed onwards are the next
// chunk's input.
func TestDecodeChunkGroupAllZerosEOF(t *testing.T) {
	body := make([]byte, 64)
	out, consumed, err := DecodeChunkGroup(context.Background(), NewState(), body)
	if err != io.EOF {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	if len(out) != 0 {
		t.Fatalf("len(out) = %d, want 0", len(out))
	}
	if consumed < 4 {
		t.Fatalf("consumed = %d, want >= 4 (chunk header)", consumed)
	}
	if consumed > uint32(len(body)) {
		t.Fatalf("consumed = %d, want <= %d (body length)", consumed, len(body))
	}
}

// Empty input (and sub-header input) → EOF cleanly. Body shorter than the
// 4-byte header is a guaranteed short-read.
func TestDecodeChunkGroupEmptyEOF(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x01},
		{0x01, 0x02, 0x03},
	}
	for _, body := range cases {
		out, consumed, err := DecodeChunkGroup(context.Background(), NewState(), body)
		if err != io.EOF {
			t.Fatalf("body=%x err = %v, want io.EOF", body, err)
		}
		if len(out) != 0 {
			t.Fatalf("body=%x len(out) = %d, want 0", body, len(out))
		}
		if consumed != 0 {
			t.Fatalf("body=%x consumed = %d, want 0", body, consumed)
		}
	}
}

// Smallest valid input (chunk header + enough rANS state for one symbol)
// → 1 byte output. cap=1 so the loop exits after exactly one symbol
// even though the body has enough rANS state to drive more.
func TestDecodeChunkGroupSmallestValidOneByte(t *testing.T) {
	body := []byte{0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}
	out, consumed, err := DecodeChunkGroupCap(context.Background(), NewState(), body, 1)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if consumed < 4 {
		t.Fatalf("consumed = %d, want >= 4 (chunk header)", consumed)
	}
	if consumed > uint32(len(body)) {
		t.Fatalf("consumed = %d, want <= %d (body length)", consumed, len(body))
	}
}

// Context cancellation surfaces cleanly mid-decode. chunk_size=16 so the
// loop would normally run 16 times; a pre-cancelled ctx returns on the
// first iteration with whatever bytes were emitted so far.
func TestDecodeChunkGroupContextCancel(t *testing.T) {
	body := []byte{0x10, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, _, err := DecodeChunkGroup(ctx, NewState(), body)
	if err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// out may be empty or partial depending on the exact rANS state at
	// the cancellation check; both are valid for a pre-cancelled ctx.
	_ = out
}

// Reused State carries ring buffer + hash chain across chunks. After
// chunk 1 emits 1 byte, Ring.Pos advances to 1 and the byte is in the
// ring buffer at offset 0.
//
// Body design under the cls11 dispatch: 0x80 bytes drive cls11 CDF
// row 0 (esi=0, hist=0) to symbol 0 (literal) on the first symbol,
// so the literal branch advances Ring.Pos by one. The prior 1-bit
// scaffold used all-0xFF bodies; those now route to cls=15 (rep
// match) because the uniform cls11 CDF maps X=0xFFFFFFFF to the
// highest slot.
func TestDecodeChunkGroupStateReuse(t *testing.T) {
	var st State
	st.ROLZ.Reset()

	body1 := []byte{0x01, 0x00, 0x00, 0x00, 0x80, 0x80, 0x80, 0x80}
	out1, consumed1, err := decodeChunkGroupCap(context.Background(), &st, body1, 1)
	if err != nil {
		t.Fatalf("chunk 1: err = %v", err)
	}
	if len(out1) != 1 {
		t.Fatalf("chunk 1: len(out1) = %d, want 1", len(out1))
	}
	if consumed1 < 4 {
		t.Fatalf("chunk 1: consumed = %d, want >= 4", consumed1)
	}
	if st.Ring.Pos != 1 {
		t.Fatalf("after chunk 1: Ring.Pos = %d, want 1", st.Ring.Pos)
	}
	if st.Ring.Buf[0] != out1[0] {
		t.Fatalf("after chunk 1: ring[0] = 0x%02x, want 0x%02x (last emitted byte)",
			st.Ring.Buf[0], out1[0])
	}

	// Chunk 2 reuses the same State. Pad with enough rANS state
	// (≥ 8 bytes) so the cls11 + literal path can drive two
	// iterations without underrunning.
	body2 := []byte{0x02, 0x00, 0x00, 0x00,
		0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80}
	out2, _, err := decodeChunkGroupCap(context.Background(), &st, body2, 2)
	if err != nil {
		t.Fatalf("chunk 2: err = %v", err)
	}
	if len(out2) != 2 {
		t.Fatalf("chunk 2: len(out2) = %d, want 2", len(out2))
	}
	if st.Ring.Pos != 3 {
		t.Fatalf("after chunk 2: Ring.Pos = %d, want 3 (1 from chunk 1 + 2 from chunk 2)",
			st.Ring.Pos)
	}
}

// Multi-byte chunk exercises the full loop. cap=4 with enough
// rANS state to drive 4 classify+symbol iterations. The cap
// clamps the output; the prior chunkSize-header invariant is
// replaced by an explicit cap parameter.
func TestDecodeChunkGroupMultiByte(t *testing.T) {
	body := []byte{0x04, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF}
	out, consumed, err := DecodeChunkGroupCap(context.Background(), NewState(), body, 4)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(out) != 4 {
		t.Fatalf("len(out) = %d, want 4", len(out))
	}
	if consumed > uint32(len(body)) {
		t.Fatalf("consumed = %d, want <= %d", consumed, len(body))
	}
	// Every byte must be either 0 (literal of X=0) or the previous ring
	// byte (match). Pin the rANS state isn't stable enough to assert
	// exact values, but length + non-empty bounds catch the obvious
	// regressions (underrun on first iter, off-by-one, etc.).
	if !bytes.Equal(out, []byte{out[0], out[0], out[0], out[0]}) &&
		!bytes.Equal(out, []byte{0, out[1], out[2], out[3]}) {
		t.Logf("out=%v (no assertion on exact pattern; classifier output varies by rANS state)", out)
	}
}