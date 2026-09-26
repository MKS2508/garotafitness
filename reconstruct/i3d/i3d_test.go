package i3d

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyConstFromOfficialPE(t *testing.T) {
	t.Parallel()
	require.Equal(t, uint32(0xE3E4E5E3), keyConst[0])
	require.Equal(t, uint32(0xE3E3E3E4), keyConst[1])
}

func TestApplyRoundTrip(t *testing.T) {
	t.Parallel()
	in := makeContainer(0x2a, 7, []byte("giants-shapes-payload"))
	once, err := Apply(in)
	require.NoError(t, err)
	require.NotEqual(t, in, once)
	require.Equal(t, in[0], once[0])
	require.Equal(t, in[1:9], once[1:9])
	twice, err := Apply(once)
	require.NoError(t, err)
	require.Equal(t, in, twice)
}

func TestApplyTruncated(t *testing.T) {
	t.Parallel()
	_, err := Apply(nil)
	require.Error(t, err)
	_, err = Apply([]byte{1, 2, 3})
	require.Error(t, err)
}

func makeContainer(seed byte, idx uint32, payload []byte) []byte {
	out := []byte{seed}
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[:4], idx)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(len(payload)))
	return append(append(out, hdr[:]...), payload...)
}
