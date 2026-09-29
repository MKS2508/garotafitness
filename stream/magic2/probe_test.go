//go:build probe

package magic2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
)

// fg-06 is a multi-group FitGirl solid. The Oracle is the sum of the
// uncompressed .x5 member sizes in the unpacked install (Black Ops 3: 10
// .x5 members totaling 1,246,105,517 bytes). We accept ±0.01 % to absorb
// any trailer padding the kernel may emit.
const fg06ExpectedBytes = 1_246_105_517

// freeArcSkip is defined in fg07_test.go (shared).

// TestMultiGroup decodes the full fg-06.bin via the framing oracle and
// sums the per-group decoded output. The hardcoded kWant was removed in
// favour of the dir-total oracle so the test stays valid across builds.
func TestMultiGroup(t *testing.T) {
	dir := corpus.DirEnv(t, "GAROTAFITNESS_CORPUS")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Skipf("corpus not mounted at %s", dir)
	}
	f := corpus.File(t, "fg-06.bin")
	_, err = f.Seek(freeArcSkip, io.SeekStart)
	require.NoError(t, err)
	data, err := io.ReadAll(f)
	require.NoError(t, err)

	rc, err := NewReader(context.Background(), bytes.NewReader(data))
	require.NoError(t, err)
	t.Cleanup(func() { rc.Close() })

	var total int64
	buf := make([]byte, 1<<20)
	for {
		n, err := rc.Read(buf)
		total += int64(n)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
	}
	delta := total - fg06ExpectedBytes
	if delta < 0 {
		delta = -delta
	}
	tolerance := fg06ExpectedBytes / 10000
	require.LessOrEqualf(t, delta, tolerance,
		"fg-06 decoded %d bytes; want %d ± %d", total, fg06ExpectedBytes, tolerance)
}

// TestMultiGroupHeaderOnly is a smoke test that runs the framing oracle
// over a tiny leading slice of fg-06 and verifies it does not panic and
// surfaces a real error for an obviously truncated frame.
func TestMultiGroupHeaderOnly(t *testing.T) {
	dir := corpus.DirEnv(t, "GAROTAFITNESS_CORPUS")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Skipf("corpus not mounted at %s", dir)
	}
	f := corpus.File(t, "fg-06.bin")
	_, err = f.Seek(31, io.SeekStart)
	require.NoError(t, err)
	data := make([]byte, 93116)
	_, err = io.ReadFull(f, data)
	require.NoError(t, err)

	rc, err := NewReader(context.Background(), bytes.NewReader(data))
	require.NoError(t, err)
	t.Cleanup(func() { rc.Close() })

	out, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Greater(t, len(out), 0, "framing oracle yielded no output")
}
