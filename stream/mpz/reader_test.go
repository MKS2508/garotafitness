package mpz

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"testing"

	"github.com/lewtec/lewkit/x/test"
	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/lucasew/garotafitness/stream/fourx4"
	"github.com/lucasew/garotafitness/stream/srep"
	"github.com/stretchr/testify/require"
)

// First member in the optional solid (FreeArc custom CRC32).
const (
	firstMP3Path = "Soundtrack/1 RimWorld Trailer Music.mp3"
	firstMP3Size = 3468604
	firstMP3CRC  = 0xf7a85e73
)

func TestNewReader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   io.Reader
		want error
	}{
		{name: "nil", want: errNil},
		{name: "empty", in: bytes.NewReader(nil), want: io.EOF},
		{name: "short", in: bytes.NewReader([]byte{0x01, 0x02}), want: io.ErrUnexpectedEOF},
		{name: "arc", in: bytes.NewReader([]byte("ArC\x01xxxx")), want: errMagic},
		{name: "srep", in: bytes.NewReader([]byte("SREP\x03\x01\x00\x00")), want: errMagic},
		{name: "ziganshin", in: bytes.NewReader([]byte{0x17, 0x18, 0x35, 0x26, 0x53, 0x52, 0x45, 0x50}), want: errMagic},
		{name: "oggre", in: bytes.NewReader([]byte("OGGRE\x00\x09\x00")), want: errMagic},
		{name: "razor", in: bytes.NewReader([]byte("CM(\x05\x06\x00\x00\x00")), want: errMagic},
		{name: "lolz", in: bytes.NewReader([]byte("DH(n\x1f\x20\x00\x00")), want: errMagic},
		{name: "id3", in: bytes.NewReader([]byte("ID3\x04\x00\x00\x00\x00")), want: errMagic},
		{name: "mp3", in: bytes.NewReader([]byte{0xff, 0xfb, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00}), want: errMagic},
		{name: "unknown", in: bytes.NewReader(bytes.Repeat([]byte{0x01}, 16)), want: errMagic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rc, err := NewReader(t.Context(), tt.in)
			require.Nil(t, rc)
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestNewReaderTagged(t *testing.T) {
	t.Parallel()
	in := frameHead(version5451, 64, 1, 0)
	rc, err := NewReader(t.Context(), bytes.NewReader(in))
	require.NoError(t, err)
	test.CloseOnCleanup(t, rc)
	n, err := rc.Read(make([]byte, 8))
	require.Zero(t, n)
	require.Error(t, err)
}

func TestFourx4Inner(t *testing.T) {
	t.Parallel()
	payload := frameHead(version5451, 8, 1, 0)
	in := frame4x4(8, payload)
	inner := func(_ context.Context, r io.Reader, name, params string) (io.ReadCloser, error) {
		require.Equal(t, "mpz", name)
		require.Empty(t, params)
		return NewReader(t.Context(), r)
	}
	rd, err := fourx4.NewReader(t.Context(), bytes.NewReader(in), "b16mb:mpz", inner)
	require.NoError(t, err)
	test.CloseOnCleanup(t, rd)
	_, err = io.ReadAll(rd)
	require.Error(t, err)
}

func TestOptionalOST(t *testing.T) {
	t.Parallel()
	f := corpus.File(t, "fg-optional-bonus-soundtrack.bin")
	_, err := f.Seek(0x1F, io.SeekStart)
	require.NoError(t, err)
	var ver [4]byte
	_, err = io.ReadFull(f, ver[:])
	require.NoError(t, err)
	require.Zero(t, binary.LittleEndian.Uint32(ver[:]))
	var hdr [8]byte
	_, err = io.ReadFull(f, hdr[:])
	require.NoError(t, err)
	outSize := binary.LittleEndian.Uint32(hdr[0:4])
	inSize := binary.LittleEndian.Uint32(hdr[4:8])
	require.Equal(t, uint32(16<<20), outSize)
	head := make([]byte, headerLen)
	_, err = io.ReadFull(f, head)
	require.NoError(t, err)
	h, err := ParseHeader(bytes.NewReader(head))
	require.NoError(t, err)
	require.Equal(t, uint32(version5451), h.Version)
	require.Equal(t, outSize, h.Orig)
	require.GreaterOrEqual(t, inSize, uint32(headerLen))
}

func TestOptionalOSTFirstMP3(t *testing.T) {
	if os.Getenv("GAROTAFITNESS_CORPUS_TESTS") == "" {
		t.Skip("set GAROTAFITNESS_CORPUS_TESTS=1 for the full MPZ block check")
	}
	t.Parallel()
	f := corpus.File(t, "fg-optional-bonus-soundtrack.bin")
	_, err := f.Seek(0x1F, io.SeekStart)
	require.NoError(t, err)
	var blk [12]byte
	_, err = io.ReadFull(f, blk[:])
	require.NoError(t, err)
	inSize := binary.LittleEndian.Uint32(blk[8:12])
	_, err = f.Seek(0x1F, io.SeekStart)
	require.NoError(t, err)
	inner := func(_ context.Context, r io.Reader, name, _ string) (io.ReadCloser, error) {
		require.Equal(t, "mpz", name)
		return NewReader(t.Context(), r)
	}
	// One 4x4 member (version + sizes + payload). Full solid is 178MiB.
	fx, err := fourx4.NewReader(t.Context(), io.LimitReader(f, int64(12+inSize)), "b16mb:mpz", inner)
	require.NoError(t, err)
	test.CloseOnCleanup(t, fx)
	got, err := io.ReadAll(fx)
	require.NoError(t, err)
	require.NotEmpty(t, got)
	require.True(t, bytes.HasPrefix(got, []byte{0x17, 0x18, 0x35, 0x26}) || bytes.HasPrefix(got, []byte("SREP")))
	sr, err := srep.NewReader(t.Context(), bytes.NewReader(got))
	require.NoError(t, err)
	test.CloseOnCleanup(t, sr)
	first := make([]byte, firstMP3Size)
	_, err = io.ReadFull(sr, first)
	require.NoError(t, err)
	sum := crc32.Checksum(first, crc32.MakeTable(0x0895171b))
	require.Equal(t, uint32(firstMP3CRC), sum)
}

func frame4x4(outSize uint32, data []byte) []byte {
	var b bytes.Buffer
	var ver [4]byte
	b.Write(ver[:])
	putU32(&b, outSize)
	putU32(&b, uint32(len(data)))
	b.Write(data)
	return b.Bytes()
}

func putU32(b *bytes.Buffer, v uint32) {
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], v)
	b.Write(p[:])
}
