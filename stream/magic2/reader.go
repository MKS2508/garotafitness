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

	"github.com/lucasew/garotafitness/internal/wasmrun"
)

//go:embed magic2dec.wasm
var guestWASM []byte

var (
	errNil   = errors.New("magic2: nil reader")
	errGuest = errors.New("magic2: guest")
)

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
	out, err := decode(ctx, body)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(out)), nil
}

func decode(ctx context.Context, body []byte) ([]byte, error) {
	if len(guestWASM) == 0 {
		return nil, errGuest
	}
	cap := len(body)*8 + 1<<20
	if cap < 4<<20 {
		cap = 4 << 20
	}
	return wasmrun.Bytes(ctx, guestWASM, "magic2_decode", cap, body)
}
