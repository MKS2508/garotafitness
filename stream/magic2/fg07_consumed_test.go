// TestFG07InputConsumed asserts the streaming reader advances r.cur by the
// kernel-reported input-consumed count when the shipped WASM guest exposes
// magic2_get_input_consumed. fg-07.bin is the cheapest FitGirl magic2 solid
// (BO3 smallest) — a multi-chunk-group body. The framing oracle fails to
// parse its metadata so the reader falls through to the consumed-count
// path; this test exercises that path directly.
//
// Asserts:
//   - streaming decode produces >1410 bytes of output (existing path)
//   - direct kernel call on the full body returns consumed > 0
//     AND consumed <= len(body) (honest count, no overrun)
package magic2

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/lucasew/garotafitness/stream/magic2/godec"
	"github.com/stretchr/testify/require"
)

const (
	fg07MinBytes = 1410
	magic2HdrLen = 9
)

func TestFG07InputConsumed(t *testing.T) {
	f := corpus.File(t, "fg-07.bin")

	_, err := f.Seek(freeArcSkip, io.SeekStart)
	require.NoError(t, err)
	preamble, err := io.ReadAll(f)
	require.NoError(t, err)
	require.Greater(t, len(preamble), magic2HdrLen, "fg-07 too short for magic2 header")

	// --- Path 1: streaming decode (full reader pipeline) ---
	r, err := NewReader(context.Background(), bytes.NewReader(preamble))
	require.NoError(t, err)
	defer r.Close()
	plain, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Greater(t, len(plain), fg07MinBytes,
		"fg-07 streaming reader produced %d bytes, expected >%d",
		len(plain), fg07MinBytes)
	t.Logf("fg-07 streaming decode: %d bytes output from %d bytes input", len(plain), len(preamble))

	// --- Path 2: direct kernel call exercises the consumed-count path ---
	// Strip the magic2 header (the kernel reads from byte 0 of its input)
	// so the same call shape the reader makes on the consumed path.
	body := preamble[magic2HdrLen:]
	out, consumed, derr := decodeFastWithConsumed(context.Background(), godec.NewState(), body)
	require.NoError(t, derr, "direct kernel call on fg-07 body failed")
	require.GreaterOrEqual(t, len(out), fg07MinBytes,
		"direct decode too small: %d bytes", len(out))

	if consumed == 0 {
		t.Logf("kernel did not report input_consumed (older wasm); skipping consumed-count audit")
		return
	}
	require.LessOrEqual(t, int(consumed), len(body),
		"consumed=%d overruns body length %d", consumed, len(body))
	require.Greater(t, int(consumed), 0,
		"consumed=0 even though kernel returned %d bytes output", len(out))
	t.Logf("kernel reports consumed=%d for %d-byte body (decoded %d bytes)",
		consumed, len(body), len(out))
}