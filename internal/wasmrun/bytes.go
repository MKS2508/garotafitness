// Package wasmrun hosts the buffer interface used by reconstruction Guests.
package wasmrun

import (
	"bytes"
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Bytes calls a Guest with (input pointer, input size) pairs, followed by an
// output pointer and capacity. The return value is the number of output bytes;
// zero signals a rejected input. Each invocation owns and releases its memory.
func Bytes(ctx context.Context, code []byte, name string, capacity int, inputs ...[]byte) ([]byte, error) {
	total := int64(capacity)
	for _, b := range inputs {
		total += int64(len(b))
	}
	if capacity <= 0 || capacity > 1<<30 || total > (2<<30)-(64<<20) {
		return nil, fmt.Errorf("%s: Guest memory limit", name)
	}
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer rt.Close(context.WithoutCancel(ctx))
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		return nil, err
	}
	if _, err := rt.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(func(uint32) {}).Export("emscripten_notify_memory_growth").
		NewFunctionBuilder().WithFunc(func(uint32, uint32, uint32, uint32, uint32) uint32 { return 0 }).Export("host_pread").
		NewFunctionBuilder().WithFunc(func(uint32, uint32, uint32, uint32, uint32) uint32 { return 0 }).Export("host_pwrite").
		NewFunctionBuilder().WithFunc(func(uint32) uint32 { return 0 }).Export("host_size_lo").
		NewFunctionBuilder().WithFunc(func(uint32) uint32 { return 0 }).Export("host_size_hi").
		Instantiate(ctx); err != nil {
		return nil, err
	}
	mod, err := rt.InstantiateWithConfig(ctx, code, wazero.NewModuleConfig().WithStartFunctions("_initialize"))
	if err != nil {
		return nil, fmt.Errorf("%s: instantiate: %w", name, err)
	}
	alloc := func(n int) (uint64, error) {
		v, err := mod.ExportedFunction("malloc").Call(ctx, uint64(max(1, n)))
		if err != nil {
			return 0, err
		}
		if v[0] == 0 {
			return 0, fmt.Errorf("%s: allocation failed", name)
		}
		return v[0], nil
	}
	var args []uint64
	for _, b := range inputs {
		p, err := alloc(len(b))
		if err != nil {
			return nil, err
		}
		if !mod.Memory().Write(uint32(p), b) {
			return nil, fmt.Errorf("%s: input outside memory", name)
		}
		args = append(args, p, uint64(len(b)))
	}
	outp, err := alloc(capacity)
	if err != nil {
		return nil, err
	}
	args = append(args, outp, uint64(capacity))
	v, err := mod.ExportedFunction(name).Call(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if v[0] == 0 || v[0] > uint64(capacity) {
		return nil, fmt.Errorf("%s: rejected input", name)
	}
	out, ok := mod.Memory().Read(uint32(outp), uint32(v[0]))
	if !ok {
		return nil, fmt.Errorf("%s: output outside memory", name)
	}
	return bytes.Clone(out), nil
}
