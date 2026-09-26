package xt2png

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseFS25Header(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/fg01.head.bin")
	require.NoError(t, err)
	h, err := parseHeader(bytes.NewReader(raw))
	require.NoError(t, err)
	require.Equal(t, int32(2), h.Depth)
	require.Equal(t, "png+preflate", h.Method)
	require.Len(t, h.Resources, 8)
	require.Zero(t, h.Compressed)
	require.Empty(t, h.Dups)
	rest := raw[headerLen(h):]
	sc, rest := i32le(rest), rest[4:]
	bs, rest := i64le(rest), rest[8:]
	require.Equal(t, int32(3), sc)
	require.Equal(t, int64(91), bs)
	var sum int32
	for i := 0; i < 3; i++ {
		sh, err := readStreamHeader(bytes.NewReader(rest[i*18:]))
		require.NoError(t, err)
		require.Equal(t, byte(kindExtended), sh.Kind)
		require.Equal(t, subPreflate, getBits(sh.Option, 0, 3))
		sum += sh.NewSize
	}
	require.Equal(t, bs, int64(sum))
	tail := i32le(rest[3*18+int(bs):])
	require.Equal(t, int32(10509958), tail)
}

func headerLen(h Header) int {
	n := 4 + 16 + 4 + 1 + len(h.Method) + 4
	for _, r := range h.Resources {
		n += 1 + len(r.Name) + 4 + len(r.Data)
	}
	n++ // flag
	return n
}

func i32le(b []byte) int32 {
	return int32(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)
}

func i64le(b []byte) int64 {
	return int64(uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56)
}
