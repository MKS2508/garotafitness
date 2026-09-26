package pages

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadRoundTrip(t *testing.T) {
	t.Parallel()
	want := bytes.Repeat([]byte("abcdef"), Size) // several pages plus remainder
	buf, err := Read(bytes.NewReader(want), int64(len(want)))
	require.NoError(t, err)
	t.Cleanup(buf.Release)
	got, err := io.ReadAll(buf.Reader())
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestReadZero(t *testing.T) {
	t.Parallel()
	buf, err := Read(bytes.NewReader(nil), 0)
	require.NoError(t, err)
	buf.Release()
	_, err = buf.Reader().Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

func TestReadShort(t *testing.T) {
	t.Parallel()
	_, err := Read(bytes.NewReader([]byte("hi")), 8)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}
