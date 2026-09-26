package xt3u

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/lewtec/lewkit/x/test"
	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/lucasew/garotafitness/stream/magic2"
	"github.com/lucasew/garotafitness/stream/srep"
	"github.com/stretchr/testify/require"
)

func TestNewReaderNilShortBadMagic(t *testing.T) {
	t.Parallel()
	_, err := NewReader(t.Context(), nil)
	require.ErrorIs(t, err, errNil)
	_, err = NewReader(t.Context(), bytes.NewReader(nil))
	require.Error(t, err)
	_, err = NewReader(t.Context(), bytes.NewReader([]byte("XXXX")))
	require.ErrorIs(t, err, errBadMagic)
	_, err = NewReader(t.Context(), bytes.NewReader([]byte("XTL")))
	require.Error(t, err)
}

func TestNewReaderTailOnly(t *testing.T) {
	t.Parallel()
	plain := []byte("hello xt3u")
	r, err := NewReader(t.Context(), bytes.NewReader(tailSolid(plain)))
	require.NoError(t, err)
	test.CloseOnCleanup(t, r)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

func TestNewReaderLZ4HC(t *testing.T) {
	t.Parallel()
	if len(guestWASM) == 0 {
		t.Skip("xt3udec.wasm not built")
	}
	raw := bytes.Repeat([]byte("Songs of Conquest "), 64)
	g, err := openGuest(t.Context())
	require.NoError(t, err)
	test.CloseOnCleanup(t, g)
	comp, err := g.compressHC(raw, 12, 0)
	require.NoError(t, err)
	opt := int32(1 | (12 << 3))
	r, err := NewReader(t.Context(), bytes.NewReader(lz4hcSolid(raw, comp, opt)))
	require.NoError(t, err)
	test.CloseOnCleanup(t, r)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, comp, got)
}

func TestParseHeaderSOC(t *testing.T) {
	src := afterMagic2SREP(t)
	h, err := parseHeader(src)
	require.NoError(t, err)
	require.Equal(t, "unity:lz4hc:l12", h.Method)
	require.Equal(t, int32(3), h.Depth)
	require.Zero(t, h.Compressed)
	require.Equal(t, int32(-1), h.StoreDD)
	require.Len(t, h.Resources, 1)
	require.Equal(t, "gk.key", h.Resources[0].Name)
	require.Len(t, h.Resources[0].Data, 32)
	require.Len(t, h.Dups, 7)
}

func TestNewReaderCorpusHead(t *testing.T) {
	src := afterMagic2SREP(t)
	r, err := NewReader(t.Context(), src)
	require.NoError(t, err)
	test.CloseOnCleanup(t, r)
	head := make([]byte, 32)
	_, err = io.ReadFull(r, head)
	require.NoError(t, err)
	require.Equal(t, []byte("<configuration>\n"), head[:len("<configuration>\n")])
}

func afterMagic2SREP(t *testing.T) io.Reader {
	t.Helper()
	f := corpus.FileEnv(t, "GAROTAFITNESS_CORPUS_SOC", "fg-03.bin")
	_, err := f.Seek(31, io.SeekStart)
	require.NoError(t, err)
	m, err := magic2.NewReader(f)
	require.NoError(t, err)
	test.CloseOnCleanup(t, m)
	s, err := srep.NewReader(t.Context(), m)
	require.NoError(t, err)
	test.CloseOnCleanup(t, s)
	return s
}

func tailSolid(plain []byte) []byte {
	var b bytes.Buffer
	b.WriteString(XTL0)
	putI32(&b, 1)  // depth
	b.WriteByte(0) // method
	putI32(&b, 0)  // resources
	putI32(&b, -2) // storeDD
	b.WriteByte(0) // compressed
	putI32(&b, 0)  // extra resources
	putI32(&b, 0)  // streamCount
	putI64(&b, 0)  // blockSize
	putU32(&b, uint32(len(plain)))
	b.Write(plain)
	putI32(&b, 0) // extra resources before terminator
	putI32(&b, int32(-1<<31))
	return b.Bytes()
}

func lz4hcSolid(raw, comp []byte, opt int32) []byte {
	var b bytes.Buffer
	b.WriteString(XTL0)
	putI32(&b, 1)
	b.WriteByte(byte(len("lz4hc:l12")))
	b.WriteString("lz4hc:l12")
	putI32(&b, 0)
	putI32(&b, -2)
	b.WriteByte(0)
	putI32(&b, 0)
	putI32(&b, 1) // one stream
	putI64(&b, int64(len(raw)))
	// TStreamHeader packed 18 bytes
	var h [streamHeaderSize]byte
	h[0] = kindDefault
	binary.LittleEndian.PutUint32(h[1:5], uint32(len(comp)))
	binary.LittleEndian.PutUint32(h[5:9], uint32(len(raw)))
	h[13] = codecLZ4
	binary.LittleEndian.PutUint32(h[14:18], uint32(opt))
	b.Write(h[:])
	b.Write(raw)
	putU32(&b, 0) // per-stream tail
	putU32(&b, 0) // final tail
	putI32(&b, 0) // extra resources before terminator
	putI32(&b, int32(-1<<31))
	return b.Bytes()
}

func putI32(b *bytes.Buffer, v int32) {
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], uint32(v))
	b.Write(p[:])
}

func putU32(b *bytes.Buffer, v uint32) {
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], v)
	b.Write(p[:])
}

func putI64(b *bytes.Buffer, v int64) {
	var p [8]byte
	binary.LittleEndian.PutUint64(p[:], uint64(v))
	b.Write(p[:])
}

func TestContainsToken(t *testing.T) {
	t.Parallel()
	require.True(t, containsToken("unity:lz4hc:l12", "lz4hc"))
	require.False(t, containsToken("unity:lz4hc:l12", "lz4h"))
	require.Contains(t, "unity:lz4hc:l12", "lz4")
}
