package lzma

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	ulzma "github.com/ulikunitz/xz/lzma"
)

func TestNewReaderRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w, err := ulzma.NewWriter(&buf)
	require.NoError(t, err)
	_, err = io.WriteString(w, "hello lzma")
	require.NoError(t, err)
	require.NoError(t, w.Close())
	r, err := NewReader(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, "hello lzma", string(got))
}
