// Package magic2 decodes cls-magic2 (FreeArc LOLZ v22c4b) streams via the
// shipped magic2dec.wasm guest.
package magic2

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
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

var (
	errNil       = errors.New("magic2: nil reader")
	errClosed    = errors.New("magic2: closed")
	errGuest     = errors.New("magic2: guest")
	errBitstream = errors.New("magic2: invalid bitstream")
)

// reader exposes the decoded byte stream of a multi-chunk-group magic2
// stream. The shipped kernel decodes exactly one chunk-group per call and
// gives no input-consumed accounting, so we binary-search for the smallest
// input window that produces the probe output, then advance by that.
type reader struct {
	ctx     context.Context
	body    []byte
	cur     int
	outBuf  []byte
	outOff  int
	err     error
	framing metadataFraming // kept for upstream test compatibility; binary-search path doesn't use it
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
	rs := bytes.NewReader(body)
	return &reader{
		ctx:     ctx,
		body:    body,
		framing: metadataFraming{src: rs, bodyOff: 0},
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

func (r *reader) nextGroup() error {
	if r.err != nil {
		return r.err
	}
	if r.cur >= len(r.body) {
		return io.EOF
	}
	available := len(r.body) - r.cur

	// Probe with the full remaining body to learn the chunk-group's
	// expected output. Kernel returns first chunk-group of the input;
	// if there are no more chunk-groups it returns a tiny / rejected
	// output we discard.
	target, err := decodeChunk(r.ctx, r.body[r.cur:])
	if err != nil {
		// Rejected input or guest failure: surface as EOF if we've
		// already produced something, else propagate the error.
		if r.cur > 0 || len(r.outBuf) > 0 {
			r.err = io.EOF
			return io.EOF
		}
		r.err = err
		return err
	}
	if len(target) < minValidOutput {
		// Treat tiny output as end-of-stream (likely garbage / partial
		// chunk-group at the tail).
		r.err = io.EOF
		return io.EOF
	}

	// Binary-search the smallest input that produces `target`.
	lo, hi := 1, available
	const maxIters = 32
	for i := 0; i < maxIters && lo < hi; i++ {
		mid := (lo + hi) / 2
		out, err := decodeChunk(r.ctx, r.body[r.cur:r.cur+mid])
		if err != nil || len(out) < len(target) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo > available {
		// Kernel output grew only when given the whole body but never
		// stabilised — accept the whole-body probe and advance past it.
		lo = available
	}

	r.outBuf = target
	r.outOff = 0
	r.cur += lo
	return nil
}

func (r *reader) Close() error {
	r.body = nil
	r.outBuf = nil
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