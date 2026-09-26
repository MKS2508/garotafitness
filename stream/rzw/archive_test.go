package rzw

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
)

func framed(b []byte) []byte {
	h := []byte{byte(len(b)), byte(len(b) >> 8), byte(len(b) >> 16), 0, 0, 0, 0}
	crc := crc32.Update(crc32.ChecksumIEEE(h[:3]), crc32.IEEETable, b)
	binary.LittleEndian.PutUint32(h[3:], crc)
	return append(h, b...)
}

func indexUint(v uint64) []byte {
	var out []byte
	for v >= 128 {
		out = append(out, byte(v<<1)|1)
		v >>= 7
	}
	return append(out, byte(v<<1))
}

func TestArchiveIndex(t *testing.T) {
	// Stream 2 occupies two runs; the first has two independently framed
	// packets and is shorter than its later run, exercising a negative delta.
	p := bytes.Repeat([]byte{0xa5}, 8)
	q := bytes.Repeat([]byte{0x5a}, 24)
	body := append(framed(p), framed(p)...)
	body = append(body, framed(p)...)
	body = append(body, framed(q)...)
	idx := indexUint(3)
	idx = append(idx, indexUint(31<<4|2)...)
	idx = append(idx, indexUint(15<<4|0)...)
	idx = append(idx, indexUint(0<<4|8|2)...)
	src := append(append([]byte{}, body...), framed(idx)...)
	r := bytes.NewReader(src)
	a, err := readArchive(r, uint64(cmLen+len(body)))
	require.NoError(t, err)
	require.Len(t, a.streams[2], 3)
	require.Equal(t, q, a.streams[2][2])
	require.Len(t, a.streams[0], 1)
	require.Zero(t, r.Len())
	for _, where := range []int{3, 7, len(body) + 3, len(src) - 1} {
		bad := bytes.Clone(src)
		bad[where] ^= 1
		_, err := readArchive(bytes.NewReader(bad), uint64(cmLen+len(body)))
		require.Error(t, err)
	}
	for cut := 0; cut < len(src); cut++ {
		_, err := readArchive(bytes.NewReader(src[:cut]), uint64(cmLen+len(body)))
		require.Error(t, err)
	}
}

func TestIndexIntegerAcrossFrames(t *testing.T) {
	want := uint64(1)<<63 | 12345
	b := indexUint(want)
	r := indexReader{src: bytes.NewReader(append(framed(b[:2]), framed(b[2:])...))}
	got, err := r.uint()
	require.NoError(t, err)
	require.Equal(t, want, got)
	r = indexReader{src: bytes.NewReader(framed(bytes.Repeat([]byte{255}, 10)))}
	_, err = r.uint()
	require.Error(t, err)
}

func TestRimWorldArchiveFrames(t *testing.T) {
	f := corpus.File(t, "fg-05.bin")
	_, err := f.Seek(31, io.SeekStart)
	require.NoError(t, err)
	h, err := parseHeader(f)
	require.NoError(t, err)
	a, err := readArchive(f, h.indexOffset)
	require.NoError(t, err)
	want := [8]int{50, 190, 992, 452, 228806}
	for i, n := range want {
		if n == 0 {
			require.Empty(t, a.streams[i])
			continue
		}
		require.Len(t, a.streams[i], 1)
		require.Len(t, a.streams[i][0], n)
	}
	pos, err := f.Seek(0, io.SeekCurrent)
	require.NoError(t, err)
	require.Equal(t, 31+int64(h.prefix), pos)
}
