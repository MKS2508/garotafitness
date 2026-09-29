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
//   - The src is read via io.SectionReader windows, not io.ReadAll, so peak
//     memory is bounded to one chunk-group's worth of input + output.
//   - The exposed Read(p) API yields decoded bytes from successive
//     chunk-groups (Ticket 2 will replace boundedWindowFraming with the
//     real per-group size oracle).
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
	// feeds each group to the same kernel; the byte stream must be
	// identical).
	direct, err := DecodeBytes(t.Context(), data[headerLen:])
	require.NoError(t, err)
	require.Equal(t, len(direct), len(got), "streaming and direct outputs must have equal length")
	require.True(t, bytes.Equal(got, direct), "streaming output differs from kernel-direct output")
}

// TestStreamingBoundedMemory verifies that the SectionReader window is
// bounded by Framing — the reader must not allocate more than maxGroupSize
// bytes of input per call, regardless of total source size.
func TestStreamingBoundedMemory(t *testing.T) {
	// 16 MiB body; default maxGroupSize is 8 MiB → at least two groups.
	const total = 16 << 20
	// Valid magic2 header (DictionarySize=1<<24, b[8]=0x01: high nibble must
	// be zero per the parser's "invalid options" check).
	hdr := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01}
	body := make([]byte, total)
	src := bytes.NewReader(append(hdr, body...))

	r, err := NewReader(context.Background(), src)
	require.NoError(t, err)
	defer r.Close()

	rd := r.(*reader)
	start, end, err := rd.framing.Next(0, int64(total))
	require.NoError(t, err)
	require.LessOrEqual(t, end-start, int64(maxGroupSize),
		"first window must be bounded by maxGroupSize")
}