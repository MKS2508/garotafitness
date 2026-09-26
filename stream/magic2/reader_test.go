package magic2

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFG06(t *testing.T) {
	f := corpus.File(t, "fg-06.bin")
	_, err := f.Seek(31, io.SeekStart)
	require.NoError(t, err)
	data := make([]byte, 93116)
	_, err = io.ReadFull(f, data)
	require.NoError(t, err)
	r, err := NewReader(bytes.NewReader(data))
	require.NoError(t, err)
	defer r.Close()
	plain, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Len(t, plain, 430889)
	got := sha256.Sum256(plain)
	// Independent reconstruction: all five original archive CRCs match.
	require.Equal(t, fg06SHA256, hex.EncodeToString(got[:]))
	for _, n := range []int{9, 14, 51, 55, len(data) - 1} {
		r, err := NewReader(bytes.NewReader(data[:n]))
		if err == nil {
			_, err = io.Copy(io.Discard, r)
			r.Close()
		}
		assert.Error(t, err)
	}
	corrupt := bytes.Clone(data)
	corrupt[55] ^= 0x80
	r, err = NewReader(bytes.NewReader(corrupt))
	if err == nil {
		_, err = io.Copy(io.Discard, r)
		r.Close()
	}
	require.Error(t, err)
}

const fg06SHA256 = "bc8242fbe8d79c30e3ccb08897f446ef95937c2ac5d5c38979182ba2a9417eab"
