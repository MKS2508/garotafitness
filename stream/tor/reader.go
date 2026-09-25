// Package tor decodes FreeArc Tornado streams (method tor).
package tor

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"

	"github.com/lucasew/garotafitness/internal/wasmrun"
)

//go:embed tordec.wasm
var guestWASM []byte

var (
	errNil   = errors.New("tor: nil reader")
	errGuest = errors.New("tor: guest")
)

// NewReader wraps an official Tornado stream as compress/gzip does.
func NewReader(ctx context.Context, r io.Reader) (io.ReadCloser, error) {
	if r == nil {
		return nil, errNil
	}
	in, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("tor: %w", err)
	}
	out, err := decode(ctx, in)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(out)), nil
}

func decode(ctx context.Context, in []byte) ([]byte, error) {
	if len(guestWASM) == 0 {
		return nil, errGuest
	}
	if len(in) == 0 {
		return nil, nil
	}
	cap := len(in)*8 + 1<<20
	if cap < 4<<20 {
		cap = 4 << 20
	}
	return wasmrun.Bytes(ctx, guestWASM, "tor_decode", cap, in)
}
