package pref

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewReader(t *testing.T) {
	t.Parallel()
	_, err := NewReader(t.Context(), nil)
	require.ErrorIs(t, err, errNil)
	_, err = NewReader(t.Context(), bytes.NewReader(nil))
	require.Error(t, err)
	_, err = NewReader(t.Context(), bytes.NewReader([]byte("ArC\x01xxxx")))
	require.Error(t, err)
}

func testdataPlain(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/plain.bin")
	if err != nil {
		t.Skip(err)
	}
	return b
}

func testdataPCF(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/plain.pcf")
	if err != nil {
		t.Skip(err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	if len(guestWASM) < 8 {
		t.Skip("prefdec.wasm not built")
	}
	plain := testdataPlain(t)
	pcf := testdataPCF(t)
	rc, err := NewReader(t.Context(), bytes.NewReader(pcf))
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	require.Equal(t, plain, got)
}

func TestInstantiateGuest(t *testing.T) {
	if len(guestWASM) < 8 {
		t.Skip("no wasm")
	}
	_, err := NewReader(t.Context(), bytes.NewReader([]byte("PCF\x00\x04\x08\x00")))
	if err == nil {
		return
	}
	require.NotContains(t, err.Error(), "is not exported")
}
