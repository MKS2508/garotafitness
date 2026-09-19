// Package fgpack reproduces the LZMA SDK 19.00 stream used to rebuild bundles.
package fgpack

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/lucasew/garotafitness/internal/wasmrun"
)

//go:embed fgpack.wasm
var guest []byte

// Encode uses the SDK defaults. The stream includes the LZMA-alone header with
// the known uncompressed size and no EOS.
func Encode(ctx context.Context, data []byte) ([]byte, error) {
	return EncodeWithOptions(ctx, data, DefaultOptions())
}

// Options are the LZMA parameters recorded in the installer's compression recipe.
type Options struct {
	DictLog, FastBytes, LC, LP, PB int
	Algo, BTMode, HashBytes        int
	ReduceToSize                   bool
}

// DefaultOptions matches the LZMA SDK encoder's default properties.
func DefaultOptions() Options { return Options{DictLog: 24, FastBytes: 32, LC: 3, LP: 0, PB: 2} }

func EncodeWithOptions(ctx context.Context, data []byte, o Options) ([]byte, error) {
	if len(data) > 512<<20 {
		return nil, fmt.Errorf("fgpack: input exceeds memory limit")
	}
	if o.DictLog < 12 || o.DictLog > 29 || o.FastBytes < 5 || o.FastBytes > 273 || o.LC < 0 || o.LC > 8 || o.LP < 0 || o.LP > 4 || o.PB < 0 || o.PB > 4 {
		return nil, fmt.Errorf("fgpack: invalid compression parameters")
	}
	return wasmrun.Bytes(ctx, guest, "fgpack_encode", len(data)+len(data)/3+65536, data, encodeConfig(o))
}
