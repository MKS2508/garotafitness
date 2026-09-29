// TestFG07 decodes the full fg-07.bin (FitGirl BO3 smallest magic2l solid)
// via the streaming reader and verifies:
//   - decode completes without error (no OOM, no bitstream panic)
//   - output is non-empty
//   - SHA256 round-trips (decoding twice yields the same hash)
//
// fg-07 is the cheapest valid FitGirl magic2 solid: ~365 KiB input,
// expected to expand to a few MiB. The streaming reader must iterate
// the framing oracle over potentially many chunk-groups without loading
// the whole body into a single kernel call.
package magic2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
)

const freeArcSkip = 31

func TestFG07(t *testing.T) {
	f := corpus.File(t, "fg-07.bin")

	_, err := f.Seek(freeArcSkip, io.SeekStart)
	require.NoError(t, err)
	body, err := io.ReadAll(f)
	require.NoError(t, err)
	require.Greater(t, len(body), 0, "fg-07 body is empty after FreeArc skip")

	r, err := NewReader(context.Background(), bytes.NewReader(body))
	require.NoError(t, err)
	defer r.Close()

	plain, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Greater(t, len(plain), 0, "fg-07 streaming reader produced no output")

	first := sha256.Sum256(plain)
	firstHex := hex.EncodeToString(first[:])
	t.Logf("fg-07 decoded: %d bytes, sha256=%s", len(plain), firstHex)

	// Round-trip: re-decode the same body, assert identical output.
	r2, err := NewReader(context.Background(), bytes.NewReader(body))
	require.NoError(t, err)
	defer r2.Close()
	plain2, err := io.ReadAll(r2)
	require.NoError(t, err)
	require.True(t, bytes.Equal(plain, plain2),
		"fg-07 decode is not deterministic: %d vs %d bytes", len(plain), len(plain2))
}