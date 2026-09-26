package xt2png

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodePNGRoundTrip(t *testing.T) {
	t.Parallel()
	orig := minimalPNG()
	enc := encodePNG(orig)
	got, err := decodePNG(enc, len(orig))
	require.NoError(t, err)
	require.Equal(t, orig, got)
}

func TestDecodePNGFlagDeNested(t *testing.T) {
	raw, err := os.ReadFile("testdata/flag-de.nested.bin")
	require.NoError(t, err)
	r := &reader{hdr: Header{Method: "png+preflate"}}
	got, err := r.restore(streamHeader{Kind: kindNested, OldSize: 86, NewSize: 1201, Codec: 5, Option: 3}, raw, nil)
	require.NoError(t, err)
	require.Len(t, got, 86)
	require.Equal(t, uint64(pngSig), binary.LittleEndian.Uint64(got[:8]))
}

func TestDecodePNGBadSig(t *testing.T) {
	t.Parallel()
	_, err := decodePNG([]byte("not a png!!!!!!!"), 16)
	require.Error(t, err)
}

func minimalPNG() []byte {
	var b []byte
	sig := [8]byte{137, 80, 78, 71, 13, 10, 26, 10}
	b = append(b, sig[:]...)
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], 1)
	binary.BigEndian.PutUint32(ihdr[4:8], 1)
	ihdr[8] = 8
	ihdr[9] = 2
	b = appendChunk(b, "IHDR", ihdr)
	idat := []byte{0x78, 0x01, 0x01, 0x04, 0x00, 0xfb, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x02, 0x00, 0x01}
	b = appendChunk(b, "IDAT", idat)
	b = appendChunk(b, "IEND", nil)
	return b
}

func encodePNG(in []byte) []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, pngSig+1)
	var payloads []byte
	cur := 8
	for cur+8 <= len(in) {
		size := int(binary.BigEndian.Uint32(in[cur:]))
		header := in[cur+4 : cur+8]
		n := 8 + size + 4
		if cur+n > len(in) {
			break
		}
		if string(header) == "IDAT" {
			out = append(out, in[cur:cur+8]...)
			out = append(out, in[cur+8+size:cur+n]...)
			payloads = append(payloads, in[cur+8:cur+8+size]...)
		} else {
			out = append(out, in[cur:cur+n]...)
		}
		cur += n
		if string(header) == "IEND" {
			break
		}
	}
	out = append(out, payloads...)
	return out
}

func appendChunk(b []byte, typ string, data []byte) []byte {
	var sz [4]byte
	binary.BigEndian.PutUint32(sz[:], uint32(len(data)))
	b = append(b, sz[:]...)
	start := len(b)
	b = append(b, typ...)
	b = append(b, data...)
	sum := crc32.ChecksumIEEE(b[start:])
	var crc [4]byte
	binary.BigEndian.PutUint32(crc[:], sum)
	return append(b, crc[:]...)
}
