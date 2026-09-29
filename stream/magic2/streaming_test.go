package magic2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/lewtec/lewkit/x/test"
	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
)

// TestStreamingSectionReaderPerGroup verifies the streaming reader:
//   - The src is loaded into memory once (io.ReadAll); peak input memory
//     is bounded by len(src).
//   - godec.DecodeSolid iterates chunk-groups internally with state
//     persisting across them; the exposed Read(p) API yields decoded
//     bytes from successive chunk-groups.
//   - Total decoded output matches the kernel's view of the whole body.
func TestStreamingSectionReaderPerGroup(t *testing.T) {
	f := corpus.File(t, "fg-06.bin")
	_, err := f.Seek(31, io.SeekStart)
	require.NoError(t, err)
	data := make([]byte, 93116)
	_, err = io.ReadFull(f, data)
	require.NoError(t, err)

	streamed, err := NewReader(t.Context(), bytes.NewReader(data))
	require.NoError(t, err)
	test.CloseOnCleanup(t, streamed)

	got, err := io.ReadAll(streamed)
	require.NoError(t, err)
	require.Len(t, got, 430889)
	sum := sha256.Sum256(got)
	require.Equal(t, fg06SHA256, hex.EncodeToString(sum[:]))

	// Whole-body kernel call must agree byte-for-byte (the streaming path
	// feeds the same input to godec; the byte stream must be identical).
	direct, err := DecodeBytes(t.Context(), data[headerLen:])
	require.NoError(t, err)
	require.Equal(t, len(direct), len(got), "streaming and direct outputs must have equal length")
	require.True(t, bytes.Equal(got, direct), "streaming output differs from kernel-direct output")
}

// TestStreamingBoundedMemory verifies that the reader's output scratch
// is bounded by solidDstCap (8 MiB), regardless of total source size.
// The input is held in full in r.body (the old per-group windowing is
// gone — godec.DecodeSolid iterates chunk-groups internally, so we
// hand it the full remaining body). Output memory is bounded.
func TestStreamingBoundedMemory(t *testing.T) {
	const total = 16 << 20
	hdr := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01}
	body := make([]byte, total)
	src := bytes.NewReader(append(hdr, body...))

	r, err := NewReader(context.Background(), src)
	require.NoError(t, err)
	defer r.Close()

	rd := r.(*reader)
	require.LessOrEqual(t, cap(rd.dst), solidDstCap,
		"output scratch must be bounded by solidDstCap")
}