package mpz

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseHeader(t *testing.T) {
	t.Parallel()
	ok := frameHead(version5451, 16777216, 19968, 0)
	h, err := ParseHeader(bytes.NewReader(ok))
	require.NoError(t, err)
	require.Equal(t, uint32(version5451), h.Version)
	require.Equal(t, uint32(16777216), h.Orig)
	require.Equal(t, uint32(19968), h.Frames)
	require.Zero(t, h.Extra)
	old := frameHead(version5450, 100, 1, 0)[:4]
	h, err = ParseHeader(bytes.NewReader(old))
	require.NoError(t, err)
	require.Equal(t, uint32(version5450), h.Version)
	require.Zero(t, h.Orig)
}

func TestParseHeaderErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{name: "empty", want: io.EOF},
		{name: "short", in: []byte{0x05, 0x04}, want: io.ErrUnexpectedEOF},
		{name: "arc", in: pad16([]byte("ArC\x01")), want: errMagic},
		{name: "unknown", in: bytes.Repeat([]byte{0x01}, 16), want: errMagic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseHeader(bytes.NewReader(tt.in))
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func frameHead(ver, orig, frames, extra uint32) []byte {
	var b [headerLen]byte
	binary.LittleEndian.PutUint32(b[0:4], ver)
	binary.LittleEndian.PutUint32(b[4:8], orig)
	binary.LittleEndian.PutUint32(b[8:12], frames)
	binary.LittleEndian.PutUint32(b[12:16], extra)
	return b[:]
}

func pad16(p []byte) []byte {
	out := make([]byte, headerLen)
	copy(out, p)
	return out
}
