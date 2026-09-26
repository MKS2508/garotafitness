package mpz

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/lewtec/lewkit/x/test"
	"github.com/stretchr/testify/require"
)

func TestRangeCodedLiterals(t *testing.T) {
	// Independently encoded literal run: selector=1, a/b/c, escape=256,
	// exhausted-output selector=1, then the five range-coder flush bytes.
	data, err := hex.DecodeString("05040501030000000000000000000000009856c49e560800")
	require.NoError(t, err)
	r, err := NewReader(t.Context(), bytes.NewReader(data))
	require.NoError(t, err)
	test.CloseOnCleanup(t, r)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, "abc", string(got))
	for n := 16; n < len(data); n++ {
		r, err := NewReader(t.Context(), bytes.NewReader(data[:n]))
		require.NoError(t, err)
		_, err = io.ReadAll(r)
		r.Close()
		require.Error(t, err)
	}
}

func TestComplementedLiterals(t *testing.T) {
	data := append(frameHead(version5450, 0, 0, 0)[:4], []byte{0, 255, 128, 127}...)
	r, err := NewReader(t.Context(), bytes.NewReader(data))
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, []byte{255, 0, 127, 128}, got)
	require.NoError(t, r.Close())
	_, err = r.Read(make([]byte, 1))
	require.ErrorIs(t, err, errClosed)
}

func TestOutputBound(t *testing.T) {
	for _, n := range []uint32{0, maxBlock + 1, ^uint32(0)} {
		_, err := NewReader(t.Context(), bytes.NewReader(frameHead(version5451, n, 0, 0)))
		require.Error(t, err)
	}
}

func TestZeroLengthReadDoesNotDecode(t *testing.T) {
	r, err := NewReader(t.Context(), bytes.NewReader(frameHead(version5451, 3, 0, 0)))
	require.NoError(t, err)
	test.CloseOnCleanup(t, r)
	n, err := r.Read(nil)
	require.NoError(t, err)
	require.Zero(t, n)
	_, err = r.Read(make([]byte, 1))
	require.Error(t, err)
}
