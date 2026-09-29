// Package magic2 — Go-native decode kernel (no WASM).
//
// wasmrun.go wraps stream/magic2/godec behind the signatures the
// streaming reader expects. The shipped magic2dec.wasm kernel was
// replaced by the Go chunk-group decoder to drop the wazero runtime and
// the embedded guest. The streaming reader allocates one godec.State
// per reader and threads it across chunk-groups so the LZ ring buffer
// and the ROLZ hash chain carry their learned context forward —
// chunk N+1 can match against chunk N's literals.
//
// decodeFast and decodeFastWithConsumed take the *State explicitly so
// the streaming reader passes &r.gst; one-shot callers (DecodeBytes)
// use godec.NewState() to seed a throwaway.
package magic2

import (
	"context"

	"github.com/lucasew/garotafitness/stream/magic2/godec"
)

func decodeFast(ctx context.Context, st *godec.State, body []byte) ([]byte, error) {
	out, _, err := decodeFastWithConsumed(ctx, st, body)
	return out, err
}

func decodeFastWithConsumed(ctx context.Context, st *godec.State, body []byte) ([]byte, uint32, error) {
	return godec.DecodeChunkGroup(ctx, st, body)
}
