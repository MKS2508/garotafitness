package xt2png

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFS25FirstChunkRestore(t *testing.T) {
	raw, err := os.ReadFile("testdata/fg01.head.bin")
	require.NoError(t, err)
	h, err := parseHeader(bytes.NewReader(raw))
	require.NoError(t, err)
	rest := raw[headerLen(h):]
	sc := i32le(rest)
	bs := i64le(rest[4:])
	require.Equal(t, int32(3), sc)
	require.Equal(t, int64(91), bs)
	rest = rest[12:]
	r := &reader{ctx: t.Context(), hdr: h}
	var got int
	off := 0
	for i := 0; i < 3; i++ {
		sh, err := readStreamHeader(bytes.NewReader(rest[i*18:]))
		require.NoError(t, err)
		payload := rest[3*18+off : 3*18+off+int(sh.NewSize)]
		off += int(sh.NewSize)
		rawp, ext, err := r.takeStreamFrom(sh, payload)
		require.NoError(t, err)
		out, err := r.restore(sh, rawp, ext)
		require.NoError(t, err)
		require.Equal(t, sh.OldSize, int32(len(out)))
		got += len(out)
	}
	require.Equal(t, 28+17+23, got)
}

func (r *reader) takeStreamFrom(h streamHeader, payload []byte) (raw, ext []byte, err error) {
	r.block = payload
	r.blockOff = 0
	return r.takeStream(h)
}
