package rzw

import (
	"bytes"
	"hash/crc32"
	"io"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/lucasew/garotafitness/stream/delta"
	"github.com/lucasew/garotafitness/stream/dispack"
	"github.com/lucasew/garotafitness/stream/srep"
	"github.com/stretchr/testify/require"
)

// fg-03.bin solid at 0x1F (rzwb). fg-04 4x4 inner packet is size+CM(.
var rzwbHead = []byte{
	0x6f, 0x04, 0x07, 0x01,
	'C', 'M', '(', 0x05, 0x06, 0x00, 0x00,
	0x33, 0xe3, 0x9c, 0x76, 0x53, 0x04, 0x07, 0x01, 0x00, 0x00,
}
var rzwHead = []byte{
	'C', 'M', '(', 0x05, 0x06, 0x00, 0x00,
	0xce, 0x2d, 0x9a, 0xe5, 0x45, 0xe2, 0x09, 0x00, 0x00, 0x00,
}

// fg-05 members after rzw → delta → dispack → srep, in archive order.
var fg05Members = []struct {
	size uint32
	crc  uint32
	path string
}{
	{613, 0xf2f30dfc, "mover/mover.bat"},
	{186, 0xf01e6380, "work/work/build01.bat"},
	{69660, 0xf1df1545, "work/work/fart.exe"},
	{108544, 0xf081f39d, "work/work/fgpack.exe"},
	{81920, 0xfd15612a, "work/work/run.exe"},
	{317952, 0xf7a6f4ee, "work/work/x.exe"},
	{38, 0xf82f659c, "work/Made by FitGirl.txt"},
	{712, 0xf01d85d3, "work/work/fitgirl01.txt"},
	{38, 0xf82f659c, "work/work/Made by FitGirl.txt"},
}

func TestNewReader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   io.Reader
		want error
	}{
		{name: "nil", want: errNil},
		{name: "empty", in: bytes.NewReader(nil), want: io.EOF},
		{name: "short", in: bytes.NewReader([]byte("CM")), want: io.ErrUnexpectedEOF},
		{name: "shortCM", in: bytes.NewReader([]byte("CM(\x05\x06\x00\x00")), want: io.ErrUnexpectedEOF},
		{name: "arc", in: bytes.NewReader([]byte("ArC\x01xxxx")), want: errMagic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rc, err := NewReader(tt.in)
			require.Nil(t, rc)
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestNewReaderTagged(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{name: "rzw", in: rzwHead},
		{name: "rzwb", in: rzwbHead},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rc, err := NewReader(bytes.NewReader(tt.in))
			require.NoError(t, err)
			t.Cleanup(func() { rc.Close() })
			n, err := rc.Read(make([]byte, 8))
			require.Zero(t, n)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		})
	}
}

func TestNewReaderVersion(t *testing.T) {
	t.Parallel()
	in := append([]byte(nil), rzwHead...)
	in[3] = 0
	rc, err := NewReader(bytes.NewReader(in))
	require.Nil(t, rc)
	require.ErrorIs(t, err, errVersion)
}

func TestNewReaderCorpus(t *testing.T) {
	t.Parallel()
	f := corpus.File(t, "fg-03.bin")
	_, err := f.Seek(0x1F, io.SeekStart)
	require.NoError(t, err)
	rc, err := NewReader(f)
	require.NoError(t, err)
	t.Cleanup(func() { rc.Close() })
	n, err := io.Copy(io.Discard, rc)
	require.NoError(t, err)
	require.NotZero(t, n)
}

func TestFG05Header(t *testing.T) {
	t.Parallel()
	f := corpus.File(t, "fg-05.bin")
	_, err := f.Seek(0x1F, io.SeekStart)
	require.NoError(t, err)
	rc, err := NewReader(f)
	require.NoError(t, err)
	t.Cleanup(func() { rc.Close() })
	require.IsType(t, &reader{}, rc)
	rd := rc.(*reader)
	require.Equal(t, uint32(230566), rd.hdr.prefix)
	require.Equal(t, uint64(230542), rd.hdr.indexOffset)
	buf := make([]byte, 8)
	n, err := rc.Read(buf)
	require.NoError(t, err)
	if n > 0 {
		t.Logf("decoded prefix %x", buf[:n])
	}
}

func TestFG05Pipeline(t *testing.T) {
	t.Parallel()
	raw := corpus.ReadFile(t, "fg-05.bin")
	solid, err := NewReader(bytes.NewReader(raw[31:]))
	require.NoError(t, err)
	t.Cleanup(func() { solid.Close() })
	del, err := delta.NewReader(solid)
	require.NoError(t, err)
	t.Cleanup(func() { del.Close() })
	dis, err := dispack.NewReader(del)
	require.NoError(t, err)
	t.Cleanup(func() { dis.Close() })
	var dhead [16]byte
	dn, derr := io.ReadFull(dis, dhead[:])
	t.Logf("dispack head n=%d %x err=%v", dn, dhead[:dn], derr)
	sr, err := srep.NewReader(t.Context(), io.MultiReader(bytes.NewReader(dhead[:dn]), dis))
	require.NoError(t, err)
	t.Cleanup(func() { sr.Close() })
	plain, err := io.ReadAll(sr)
	require.NoError(t, err)
	off := 0
	matched := 0
	for _, m := range fg05Members {
		require.LessOrEqual(t, off+int(m.size), len(plain))
		// Custom FreeArc polynomial recovered from the installer unarc DLL.
		got := crc32.Checksum(plain[off:off+int(m.size)], crc32.MakeTable(0x0895171b))
		require.Equal(t, m.crc, got)
		t.Logf("ok %8d %08x %s", m.size, m.crc, m.path)
		off += int(m.size)
		matched++
	}
	require.Equal(t, len(fg05Members), matched)
	require.Equal(t, len(plain), off)
}
