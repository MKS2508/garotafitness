package dispack

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/stretchr/testify/require"
)

func TestTagData(t *testing.T) {
	t.Parallel()
	plain := []byte("hello dispack")
	in := packData(16*1024, plain)
	rd, err := NewReader(bytes.NewReader(in))
	require.NoError(t, err)
	got, err := io.ReadAll(rd)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

func TestOfficialCode(t *testing.T) {
	t.Parallel()
	assertEXE(t, "code.filt", "code.plain")
}

func TestOfficialJumpTable(t *testing.T) {
	t.Parallel()
	assertEXE(t, "jumptab.filt", "jumptab.plain")
}

func TestUnfilterDirect(t *testing.T) {
	t.Parallel()
	td := testdataRoot(t)
	src, err := lewpath.New("code.filt").ReadFile(td)
	require.NoError(t, err)
	want, err := lewpath.New("code.plain").ReadFile(td)
	require.NoError(t, err)
	got := make([]byte, len(want))
	require.True(t, unfilter(src, got, baseStart))
	require.Equal(t, want, got)
}

func TestNewReaderNil(t *testing.T) {
	t.Parallel()
	_, err := NewReader(nil)
	require.Error(t, err)
}

func TestEmpty(t *testing.T) {
	t.Parallel()
	rd, err := NewReader(bytes.NewReader(nil))
	require.NoError(t, err)
	got, err := io.ReadAll(rd)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestBadTag(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	putU32(&b, 16*1024)
	putU32(&b, tagData+3)
	rd, err := NewReader(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)
	_, err = io.ReadAll(rd)
	require.Error(t, err)
}

func assertEXE(t *testing.T, filt, plain string) {
	t.Helper()
	td := testdataRoot(t)
	src, err := lewpath.New(filt).ReadFile(td)
	require.NoError(t, err)
	want, err := lewpath.New(plain).ReadFile(td)
	require.NoError(t, err)
	in := packEXE(16*1024, src, uint32(len(want)))
	rd, err := NewReader(bytes.NewReader(in))
	require.NoError(t, err)
	got, err := io.ReadAll(rd)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func packData(chunk uint32, data []byte) []byte {
	var b bytes.Buffer
	putU32(&b, chunk)
	putU32(&b, tagData)
	putU32(&b, uint32(len(data)))
	b.Write(data)
	return b.Bytes()
}

func packEXE(chunk uint32, filt []byte, outSize uint32) []byte {
	var b bytes.Buffer
	putU32(&b, chunk)
	putU32(&b, tagEXE)
	putU32(&b, outSize)
	putU32(&b, uint32(len(filt)))
	b.Write(filt)
	return b.Bytes()
}

func putU32(b *bytes.Buffer, v uint32) {
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], v)
	b.Write(p[:])
}
