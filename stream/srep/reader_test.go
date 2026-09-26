package srep

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/lewtec/lewkit/x/test"
	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
)

var futureLZHead = []byte{
	0x17, 0x18, 0x35, 0x26,
	0x53, 0x52, 0x45, 0x50,
	0x03, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

func TestNewReader(t *testing.T) {
	t.Parallel()
	_, err := NewReader(t.Context(), nil)
	require.Error(t, err)
	_, err = NewReader(t.Context(), bytes.NewReader([]byte("ArC\x01")))
	require.Error(t, err)
	r, err := NewReader(t.Context(), bytes.NewReader(futureLZHead))
	require.NoError(t, err)
	test.CloseOnCleanup(t, r)
	n, err := r.Read(make([]byte, 8))
	require.Zero(t, n)
	require.Equal(t, io.EOF, err)
}

func TestNewReaderLiterals(t *testing.T) {
	t.Parallel()
	plain := []byte("hello")
	r, err := NewReader(t.Context(), bytes.NewReader(literalSolid(plain)))
	require.NoError(t, err)
	test.CloseOnCleanup(t, r)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

func TestNewReaderCorpus(t *testing.T) {
	t.Parallel()
	f := corpus.File(t, "fg-01.bin")
	_, err := f.Seek(0x1F, io.SeekStart)
	require.NoError(t, err)
	r, err := NewReader(t.Context(), f)
	require.NoError(t, err)
	test.CloseOnCleanup(t, r)
	buf := make([]byte, 5)
	_, err = io.ReadFull(r, buf)
	require.NoError(t, err)
	require.Equal(t, "OGGRE", string(buf))
	// FreeArc trailer after the last literal block is not an SREP header.
	n, err := io.Copy(io.Discard, r)
	require.NoError(t, err)
	// 5 bytes already read + remainder = 216364145
	require.Equal(t, int64(216364145), n+5)
}

func literalSolid(plain []byte) []byte {
	var b bytes.Buffer
	b.Write(futureLZHead)
	var hdr [12]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(plain)))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(len(plain)))
	b.Write(hdr[:])
	b.Write(make([]byte, 16))
	b.Write(plain)
	return b.Bytes()
}
