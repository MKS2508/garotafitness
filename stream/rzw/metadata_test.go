package rzw

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRimWorldMetadata(t *testing.T) {
	// The complete 50-byte entropy payload from fg-05's metadata frame.
	packet, err := hex.DecodeString("b38da51816bf8d82b6ba93adbb5b30c177e4a778822f0b6353c6c67a150cd4c724377a6eeb0fe176a09c753e5d03b9ae3900")
	require.NoError(t, err)
	got, err := readMetadata([][]byte{packet})
	require.NoError(t, err)
	want := metadata{window: 1 << 20, files: []fileRecord{
		{name: "rzr3878", time: 0x31c2ad0a5, attributes: 0x10, parent: -1},
		{name: "f1", size: 0x835e1, time: 0x31c2ad0a5, crc: 0x88ecbedd, attributes: 0x20, parent: 0},
	}}
	require.Equal(t, want, got)
	for n := 0; n < len(packet); n++ {
		_, err := readMetadata([][]byte{packet[:n]})
		require.Error(t, err)
	}
}
