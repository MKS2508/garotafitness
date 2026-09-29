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
// stream. Boundary detection follows the cls-magic2 algorithm (RE of
// FUN_140037790, FUN_14003afc0, FUN_140028a40):
//
//   - FUN_14003afc0 parses the per-chunk-group metadata block and decodes the
//     rANS-encoded `local_7c` (chunk_group_uncompressed_size) into model
//     state. FUN_140028a40 then calls FUN_140037790 with that as param_2.
//   - FUN_140037790's loop decrements `local_c0` (= param_2) by
//     bytes_decoded each chunk-group iteration and returns when it hits 0,
//     producing exactly param_2 bytes per chunk-group. The host tracks the
//     input position via param_1[0x1e] (= bytes consumed, byte-aligned per
//     symbol).
//
// The shipped WASM exposes that count as magic2_get_input_consumed so the
// streaming reader advances r.cur by exactly the kernel-reported offset
// instead of bisecting. If the export is missing or returns 0 (older guest,
// CRC-fallback path that re-decodes the whole buffer), we fall back to the
// binary-search probe — same contract as before, just slower.
type reader struct {
	ctx     context.Context
	body    []byte
	cur     int
	outBuf  []byte
	outOff  int
	err     error
	framing metadataFraming
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

// nextGroup decodes the next chunk-group into r.outBuf and advances r.cur.
// Strategy:
//  1. Framing-driven (cls-magic2 algorithm): ask the framing oracle for the
//     next chunk-group's [start, end) in body coordinates and its declared
//     uncompressed output size (seg.size = param_2 in FUN_140037790). One
//     kernel call with body[start:end] — if the output matches the declared
//     size, accept it and advance to end.
//  2. Direct kernel probe with the kernel-reported input-consumed count:
//     one kernel call on the remaining body, then advance r.cur by exactly
//     the bytes the kernel actually read. Used when framing fails (EOF,
//     corrupt metadata, missing chunk header) and the shipped guest exposes
//     magic2_get_input_consumed.
//  3. Binary-search fallback: same shape as before — used when the export
//     is missing or returned 0 (e.g. CRC-fallback re-decode of the whole
//     body). Identical probe semantics to the previous implementation.
func (r *reader) nextGroup() error {
	if r.err != nil {
		return r.err
	}
	if r.cur >= len(r.body) {
		return io.EOF
	}

	// --- Path 1: framing-driven (cls-magic2 chunk-group algorithm) ---
	start, end, expectedOut, ferr := r.framing.Next(int64(r.cur), int64(len(r.body)))
	if ferr == nil && end > start {
		out, consumed, derr := decodeFastWithConsumed(r.ctx, r.body[start:end])
		if derr == nil && len(out) > 0 && (expectedOut <= 0 || int64(len(out)) == expectedOut) {
			r.outBuf = out
			r.outOff = 0
			_ = consumed // framing already pinned end; kernel agrees
			r.cur = int(end)
			return nil
		}
		// Decode failed or output mismatched the declared size: treat as if
		// framing was correct but the kernel disagrees. Fall through to the
		// consumed/probe path so we don't strand the stream at r.cur.
	}

	// --- Path 2: single-call with kernel-reported consumption ---
	probeOut, consumed, err := decodeFastWithConsumed(r.ctx, r.body[r.cur:])
	if err == nil && consumed > 0 && len(probeOut) >= minValidOutput {
		r.outBuf = probeOut
		r.outOff = 0
		r.cur += int(consumed)
		return nil
	}
	// Stash for the binary-search path: a usable probe without a
	// consumption count, or a kernel error that we'll surface as EOF.
	bsProbe := probeOut
	bsErr := err

	// --- Path 3: binary-search fallback ---
	if bsErr != nil {
		// Rejected input or guest failure: surface as EOF if we've
		// already produced something, else propagate the error.
		if r.cur > 0 || len(r.outBuf) > 0 {
			r.err = io.EOF
			return io.EOF
		}
		r.err = bsErr
		return bsErr
	}
	if len(bsProbe) < minValidOutput {
		// Treat tiny output as end-of-stream (likely garbage / partial
		// chunk-group at the tail).
		r.err = io.EOF
		return io.EOF
	}

	probeOut = bsProbe
	available := len(r.body) - r.cur
	lo, hi := 1, available
	const maxIters = 32
	for i := 0; i < maxIters && lo < hi; i++ {
		mid := (lo + hi) / 2
		out, err := decodeChunk(r.ctx, r.body[r.cur:r.cur+mid])
		// Termination oracle: when the kernel has the full chunk-group in
		// its input window, it produces exactly len(probeOut) bytes. If it
		// returns fewer, the window is too small. If it returns the same or
		// more, the window covers (at least) one chunk-group.
		if err != nil || len(out) < len(probeOut) {
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

	r.outBuf = probeOut
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