// Package magic2 decodes cls-magic2 (FreeArc LOLZ v22c4b) streams.
// The streaming reader uses the pure-Go godec package as the primary
// decode path and falls back to the shipped magic2dec.wasm kernel
// when godec produces no output (e.g. simplified classifier missing
// a real cls=11 / hit_crc match on a stub corpus).
package magic2

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"

	"github.com/lucasew/garotafitness/stream/magic2/godec"
)

//go:embed magic2dec.wasm
var guestWASM []byte

// maxGroupSize caps each kernel call's input. The shipped kernel decodes
// exactly one chunk-group per call and terminates on rANS ansLower, so
// feeding it up to this many bytes is safe (anything beyond the natural
// chunk-group boundary is ignored).
const maxGroupSize = 8 << 20

// minValidOutput filters the binary-search probe: outputs below this size
// are typically garbage from a partial / insufficient decode, not a real
// chunk-group. The first known-good chunk-group in fg-06 is 430889 bytes,
// well above this threshold.
const minValidOutput = 1024

// solidDstCap is the dst capacity handed to godec.DecodeSolid per
// streaming Read. One solid's decoded output can run into the
// hundreds of MiB (fg-01 is ~33 GiB); we allocate a generous 8 MiB
// scratch and let DecodeSolid fill it as much as fits, then loop.
// Per-call caps this is the streaming reader's cost — the WASM
// kernel uses the same cap shape.
const solidDstCap = 8 << 20

var (
	errNil       = errors.New("magic2: nil reader")
	errClosed    = errors.New("magic2: closed")
	errGuest     = errors.New("magic2: guest")
	errBitstream = errors.New("magic2: invalid bitstream")
)

// reader exposes the decoded byte stream of a multi-chunk-group magic2
// stream. The primary decode path is godec.DecodeSolid — it iterates
// chunk-groups internally with state persisting across them, which
// restores the cls11 mode + freq-table + hash-chain history the prior
// per-chunk-group caller pattern was losing. WASM kernel fallback
// remains for cases where godec produces no output (stub corpus,
// simplified classifier, real magic2 hits that the port doesn't yet
// model).
type reader struct {
	ctx  context.Context
	body []byte
	cur  int
	st   *godec.State // per-solid godec state; persists across nextGroup() calls
	dst  []byte      // scratch for godec.DecodeSolid output

	outBuf []byte
	outOff int
	err    error
}

func NewReader(ctx context.Context, src io.Reader) (io.ReadCloser, error) {
	if src == nil {
		return nil, errNil
	}
	if _, err := ParseHeader(src); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(src)
	if err != nil {
		return nil, fmt.Errorf("magic2: read body: %w", err)
	}
	return &reader{
		ctx:  ctx,
		body: body,
		st:   godec.NewState(),
		dst:  make([]byte, solidDstCap),
	}, nil
}

func (r *reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for r.outOff >= len(r.outBuf) {
		if err := r.nextGroup(); err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, err
		}
	}
	n := copy(p, r.outBuf[r.outOff:])
	r.outOff += n
	return n, nil
}

// nextGroup decodes the next batch of bytes from the solid and
// advances r.cur. Primary path is godec.DecodeSolid (one call iterates
// chunk-groups internally, returning decoded bytes + consumed input).
// Fallback path is the WASM kernel — used when godec produces no
// output (real magic2 streams the simplified classifier hasn't been
// taught yet). On a fallback hit the kernel's reported consumed
// count advances r.cur; without it, the binary-search probe keeps
// the old contract.
func (r *reader) nextGroup() error {
	if r.err != nil {
		return r.err
	}
	if r.cur >= len(r.body) {
		return io.EOF
	}

	// --- Path 1: godec.DecodeSolid (pure-Go, primary) ---
	n, consumed, err := godec.DecodeSolid(r.ctx, r.st, r.body[r.cur:], r.dst)
	if err == nil && n > 0 && consumed > 0 {
		// Append-style copy into a fresh slice sized to n. We do
		// not reuse r.dst across calls because the next call's
		// DecodeSolid would overwrite it.
		out := make([]byte, n)
		copy(out, r.dst[:n])
		r.outBuf = out
		r.outOff = 0
		r.cur += consumed
		return nil
	}

	// --- Path 2: WASM kernel fallback ---
	// godec produced no output (or context cancelled). Try the
	// shipped kernel; if it succeeds we accept the result and
	// don't strand r.cur. The kernel's per-call consumed count
	// is the new advance signal.
	probeOut, kConsumed, kerr := decodeFastWithConsumed(r.ctx, r.body[r.cur:])
	if kerr == nil && kConsumed > 0 && len(probeOut) >= minValidOutput {
		r.outBuf = probeOut
		r.outOff = 0
		r.cur += int(kConsumed)
		return nil
	}
	if kerr != nil {
		if r.cur > 0 || len(r.outBuf) > 0 {
			r.err = io.EOF
			return io.EOF
		}
		r.err = kerr
		return kerr
	}

	// --- Path 3: binary-search fallback (kernel probe only) ---
	if len(probeOut) < minValidOutput {
		r.err = io.EOF
		return io.EOF
	}
	available := len(r.body) - r.cur
	lo, hi := 1, available
	const maxIters = 32
	for i := 0; i < maxIters && lo < hi; i++ {
		mid := (lo + hi) / 2
		out, err := decodeChunk(r.ctx, r.body[r.cur:r.cur+mid])
		if err != nil || len(out) < len(probeOut) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo > available {
		lo = available
	}
	r.outBuf = probeOut
	r.outOff = 0
	r.cur += lo
	return nil
}

func (r *reader) Close() error {
	r.body = nil
	r.outBuf = nil
	r.dst = nil
	r.st = nil
	if r.err == nil || errors.Is(r.err, io.EOF) {
		r.err = errClosed
	}
	return nil
}

// DecodeBytes decodes a single body buffer via the WASM kernel without
// streaming. Used by tests for direct round-trip comparison and by callers
// that already know they have exactly one chunk-group.
func DecodeBytes(ctx context.Context, body []byte) ([]byte, error) {
	return decodeFast(ctx, body)
}

func decodeChunk(ctx context.Context, chunk []byte) ([]byte, error) {
	return decodeFast(ctx, chunk)
}

// ensure bytes package is referenced (kept for symmetry with sibling files)
var _ = bytes.NewReader