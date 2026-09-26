package srep

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseHeaderFutureLZ(t *testing.T) {
	t.Parallel()
	// fg-01.bin solid at 0x1F
	in := []byte{
		0x17, 0x18, 0x35, 0x26,
		0x53, 0x52, 0x45, 0x50,
		0x03, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	h, err := ParseHeader(bytes.NewReader(in))
	require.NoError(t, err)
	require.Equal(t, FormatFutureLZ, h.Format)
	require.Equal(t, uint8(1), h.HashNum)
	require.Zero(t, h.BaseLen)
}

func TestParseHeaderRejectsArc(t *testing.T) {
	t.Parallel()
	_, err := ParseHeader(bytes.NewReader([]byte("ArC\x01\x00\x00\x06\x07storing!!")))
	require.Error(t, err)
}
