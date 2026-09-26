package mpzz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarshalSplit255Laces(t *testing.T) {
	h := pageHeader{flags: 0, granule: 1, serial: 2, sequence: 3}
	// 200 packets of 300 bytes = 400 laces (255+45 each).
	body := make([]byte, 200*300)
	for i := 0; i < 200; i++ {
		h.packets = append(h.packets, 300)
		h.lacing = append(h.lacing, 255, 45)
	}
	out, err := h.marshal(body)
	require.NoError(t, err)
	pages, off := 0, 0
	for off < len(out) {
		require.Equal(t, "OggS", string(out[off:off+4]))
		nseg := int(out[off+26])
		require.NotZero(t, nseg)
		require.LessOrEqual(t, nseg, 255)
		size := 27 + nseg
		for _, s := range out[off+27 : off+27+nseg] {
			size += int(s)
		}
		off += size
		pages++
	}
	require.GreaterOrEqual(t, pages, 2)
}
