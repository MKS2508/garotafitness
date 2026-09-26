package mpzz

import (
	"bytes"
	"encoding/hex"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/test"
	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/lucasew/garotafitness/stream/srep"
	"github.com/stretchr/testify/require"
)

// fg-01 after SREP: testdata/header.hex.
var fg01Head = []byte{
	'O', 'G', 'G', 'R', 'E', 0x00, 0x09, 0xf9,
	0x12, 0x8c, 0xaa, 0xb3, 0xee, 0xae, 0x5c, 0xde,
}

const (
	fg01InnerSize = 255994514
	fg01InnerCRC  = 0xf7a300d7
	fg01SolidOff  = 0x1F
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
		{name: "short", in: bytes.NewReader([]byte("OGG")), want: io.ErrUnexpectedEOF},
		{name: "arc", in: bytes.NewReader([]byte("ArC\x01x")), want: errMagic},
		{name: "ogg", in: bytes.NewReader([]byte("OggS\x00")), want: errMagic},
		{name: "ver", in: bytes.NewReader([]byte("OGGRE\x01\x09")), want: errVersion},
		{name: "stat", in: bytes.NewReader([]byte("OGGRE\x00\x04")), want: errFlags},
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

func TestSlurpReaderAt(t *testing.T) {
	t.Parallel()
	want := []byte("OGGRE\x00\x09hello")
	got, err := slurp(bytes.NewReader(want))
	require.NoError(t, err)
	require.Equal(t, want, got)
	got, err = slurp(test.OnlyReader{Reader: bytes.NewReader(want)})
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestNewReaderOGGRE(t *testing.T) {
	t.Parallel()
	rc, err := NewReader(t.Context(), bytes.NewReader(fg01Head))
	require.NoError(t, err)
	test.CloseOnCleanup(t, rc)
	n, err := rc.Read(make([]byte, 8))
	require.Zero(t, n)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestHeaderHex(t *testing.T) {
	t.Parallel()
	raw, err := lewpath.New("header.hex").ReadFile(testdataRoot(t))
	require.NoError(t, err)
	var hexDigits strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		hexDigits.WriteString(strings.Map(func(r rune) rune {
			if strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return r
			}
			return -1
		}, line))
	}
	got, err := hex.DecodeString(hexDigits.String())
	require.NoError(t, err)
	require.Equal(t, fg01Head, got)
}

func TestNewReaderCorpus(t *testing.T) {
	t.Parallel()
	f := corpus.File(t, "fg-01.bin")
	_, err := f.Seek(fg01SolidOff, io.SeekStart)
	require.NoError(t, err)
	sr, err := srep.NewReader(t.Context(), f)
	require.NoError(t, err)
	test.CloseOnCleanup(t, sr)
	rc, err := NewReader(t.Context(), sr)
	require.NoError(t, err)
	test.CloseOnCleanup(t, rc)
	h := crc32.New(crc32.MakeTable(0x0895171b))
	n, err := io.Copy(h, rc)
	require.NoError(t, err)
	require.Equal(t, int64(fg01InnerSize), n)
	require.Equal(t, uint32(fg01InnerCRC), h.Sum32())
}
