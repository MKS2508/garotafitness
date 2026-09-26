package rzw

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCopyHistory(t *testing.T) {
	d := newDec(nil, 32)
	require.True(t, d.copyHistory(0xff0, 4))
	require.Equal(t, make([]byte, 4), d.out)
	d.emit('a')
	d.emit('b')
	require.True(t, d.copyHistory(2, 6))
	require.Equal(t, "abababab", string(d.out[4:]))
	before := bytes.Clone(d.out)
	for _, match := range [][2]int{{0, 1}, {d.pos + 0xff1, 1}, {1, 33}} {
		require.False(t, d.copyHistory(match[0], match[1]))
		require.Equal(t, before, d.out)
	}
}

func TestEntropyOutputLimit(t *testing.T) {
	packet, err := hex.DecodeString("b38da51816bf8d82b6ba93adbb5b30c177e4a778822f0b6353c6c67a150cd4c724377a6eeb0fe176a09c753e5d03b9ae3900")
	require.NoError(t, err)
	for limit := 1; limit < 75; limit++ {
		_, err := decodeFrames([][]byte{packet}, limit)
		require.Error(t, err)
	}
	got, err := decodeFrames([][]byte{packet}, 75)
	require.NoError(t, err)
	require.Len(t, got, 75)
}
