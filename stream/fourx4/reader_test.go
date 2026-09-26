package fourx4

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseInner(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, name, params string
	}{
		{"b128mb:rzw", "rzw", ""},
		{"b16mb:mpz", "mpz", ""},
		{"t4:i2:b8mb:lzma:8mb", "lzma", "8mb"},
		{"rzw", "rzw", ""},
		{"r99:rzw", "rzw", ""},
	}
	for _, tc := range cases {
		name, params, err := parseInner(tc.in)
		require.NoError(t, err)
		require.Equal(t, tc.name, name)
		require.Equal(t, tc.params, params)
	}
	_, _, err := parseInner("")
	require.Error(t, err)
	_, _, err = parseInner("b128mb")
	require.Error(t, err)
}

func TestNewReaderNil(t *testing.T) {
	t.Parallel()
	_, err := NewReader(t.Context(), nil, "rzw", ident)
	require.Error(t, err)
	_, err = NewReader(t.Context(), bytes.NewReader(nil), "rzw", nil)
	require.Error(t, err)
}

func TestStoredRoundTrip(t *testing.T) {
	t.Parallel()
	plain := []byte("hello 4x4 stored")
	var called bool
	inner := func(_ context.Context, r io.Reader, name, params string) (io.ReadCloser, error) {
		called = true
		return ident(t.Context(), r, name, params)
	}
	in := frameStored(plain)
	rd, err := NewReader(t.Context(), bytes.NewReader(in), "b128mb:rzw", inner)
	require.NoError(t, err)
	got, err := io.ReadAll(rd)
	require.NoError(t, err)
	require.Equal(t, plain, got)
	require.False(t, called)
}

func TestInnerCompressed(t *testing.T) {
	t.Parallel()
	plain := []byte("inner payload")
	var gotName, gotParams string
	inner := func(_ context.Context, r io.Reader, name, params string) (io.ReadCloser, error) {
		gotName, gotParams = name, params
		b, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		for i := range b {
			b[i] ^= 0x5a
		}
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	comp := append([]byte(nil), plain...)
	for i := range comp {
		comp[i] ^= 0x5a
	}
	in := frameComp(uint32(len(plain)), comp)
	rd, err := NewReader(t.Context(), bytes.NewReader(in), "b16mb:mpz:q1", inner)
	require.NoError(t, err)
	got, err := io.ReadAll(rd)
	require.NoError(t, err)
	require.Equal(t, plain, got)
	require.Equal(t, "mpz", gotName)
	require.Equal(t, "q1", gotParams)
}

func TestManyBlocksOrder(t *testing.T) {
	t.Parallel()
	var framed bytes.Buffer
	var ver [4]byte
	framed.Write(ver[:])
	var want bytes.Buffer
	for i := 0; i < 8; i++ {
		plain := []byte(fmt.Sprintf("block-%02d-payload", i))
		want.Write(plain)
		comp := append([]byte(nil), plain...)
		for j := range comp {
			comp[j] ^= 0x5a
		}
		putU32(&framed, uint32(len(plain)))
		putU32(&framed, uint32(len(comp)))
		framed.Write(comp)
	}
	inner := func(_ context.Context, r io.Reader, _, _ string) (io.ReadCloser, error) {
		b, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		for i := range b {
			b[i] ^= 0x5a
		}
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	rd, err := NewReader(t.Context(), bytes.NewReader(framed.Bytes()), "t4:rzw", inner)
	require.NoError(t, err)
	got, err := io.ReadAll(rd)
	require.NoError(t, err)
	require.Equal(t, want.String(), string(got))
}

func TestParseThreads(t *testing.T) {
	t.Parallel()
	require.Equal(t, 4, parseThreads("t4:b8mb:rzw"))
	require.GreaterOrEqual(t, parseThreads("rzw"), 1)
}

func TestEmptyStream(t *testing.T) {
	t.Parallel()
	rd, err := NewReader(t.Context(), bytes.NewReader(nil), "rzw", ident)
	require.NoError(t, err)
	got, err := io.ReadAll(rd)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestBadVersion(t *testing.T) {
	t.Parallel()
	in := []byte{1, 0, 0, 0}
	_, err := NewReader(t.Context(), bytes.NewReader(in), "rzw", ident)
	require.Error(t, err)
}

func TestInnerError(t *testing.T) {
	t.Parallel()
	boom := func(context.Context, io.Reader, string, string) (io.ReadCloser, error) {
		return nil, fmt.Errorf("nope")
	}
	in := frameComp(4, []byte("xxxx"))
	rd, err := NewReader(t.Context(), bytes.NewReader(in), "rzw", boom)
	require.NoError(t, err)
	_, err = io.ReadAll(rd)
	require.Error(t, err)
}

func ident(_ context.Context, r io.Reader, _, _ string) (io.ReadCloser, error) {
	return io.NopCloser(r), nil
}

func frameStored(data []byte) []byte {
	var b bytes.Buffer
	var ver [4]byte
	b.Write(ver[:])
	putU32(&b, storedOut)
	putU32(&b, uint32(len(data)))
	b.Write(data)
	return b.Bytes()
}

func frameComp(outSize uint32, data []byte) []byte {
	var b bytes.Buffer
	var ver [4]byte
	b.Write(ver[:])
	putU32(&b, outSize)
	putU32(&b, uint32(len(data)))
	b.Write(data)
	return b.Bytes()
}

func putU32(b *bytes.Buffer, v uint32) {
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], v)
	b.Write(p[:])
}
