// Cached wrapper around the magic2dec.wasm kernel. Re-uses one
// wazero.CompilationCache across calls so the ~3 s module compilation
// only happens once per process. Drop-in replacement for
// internal/wasmrun.Bytes for the magic2 kernel.
package magic2

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

var (
	cacheOnce sync.Once
	warmCache wazero.CompilationCache
)

func getCache() wazero.CompilationCache {
	cacheOnce.Do(func() { warmCache = wazero.NewCompilationCache() })
	return warmCache
}

// decodeFast mirrors internal/wasmrun.Bytes but threads a wazero
// compilation cache so subsequent calls reuse the compiled module. The
// kernel API is (src, slen, dst, dcap) -> bytes_written.
func decodeFast(ctx context.Context, body []byte) ([]byte, error) {
	out, _, err := decodeFastWithConsumed(ctx, body)
	return out, err
}

// decodeFastWithConsumed runs magic2_decode and, when the shipped guest
// exposes it, magic2_get_input_consumed in the same wazero session and
// returns the input byte offset the kernel actually read. The streaming
// reader advances r.cur by exactly that amount instead of bisecting.
//
// Falls back to inputConsumed=0 on any export/call failure: callers must
// then keep the binary-search path. Returns the decoded bytes and the
// kernel-reported consumption atomically per call.
func decodeFastWithConsumed(ctx context.Context, body []byte) ([]byte, uint32, error) {
	if len(guestWASM) == 0 {
		return nil, 0, errGuest
	}
	cap := len(body)*8 + 1<<20
	if cap < 4<<20 {
		cap = 4 << 20
	}
	if cap <= 0 || cap > 1<<30 {
		return nil, 0, fmt.Errorf("magic2_decode: capacity %d out of range", cap)
	}
	if int64(cap)+int64(len(body)) > (2<<30)-(64<<20) {
		return nil, 0, fmt.Errorf("magic2_decode: input + cap too large")
	}
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithCompilationCache(getCache()))
	defer rt.Close(context.WithoutCancel(ctx))
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		return nil, 0, fmt.Errorf("magic2_decode: wasi: %w", err)
	}
	if _, err := rt.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(func(uint32) {}).Export("emscripten_notify_memory_growth").
		NewFunctionBuilder().WithFunc(func(uint32, uint32, uint32, uint32, uint32) uint32 { return 0 }).Export("host_pread").
		NewFunctionBuilder().WithFunc(func(uint32, uint32, uint32, uint32, uint32) uint32 { return 0 }).Export("host_pwrite").
		NewFunctionBuilder().WithFunc(func(uint32) uint32 { return 0 }).Export("host_size_lo").
		NewFunctionBuilder().WithFunc(func(uint32) uint32 { return 0 }).Export("host_size_hi").
		Instantiate(ctx); err != nil {
		return nil, 0, fmt.Errorf("magic2_decode: env: %w", err)
	}
	mod, err := rt.InstantiateWithConfig(ctx, guestWASM, wazero.NewModuleConfig().WithStartFunctions("_initialize"))
	if err != nil {
		return nil, 0, fmt.Errorf("magic2_decode: instantiate: %w", err)
	}
	malloc := mod.ExportedFunction("malloc")
	kernel := mod.ExportedFunction("magic2_decode")
	alloc := func(n int) (uint32, error) {
		v, err := malloc.Call(ctx, uint64(n))
		if err != nil {
			return 0, err
		}
		if v[0] == 0 {
			return 0, errors.New("magic2_decode: malloc returned 0")
		}
		return uint32(v[0]), nil
	}
	inp, err := alloc(len(body))
	if err != nil {
		return nil, 0, fmt.Errorf("magic2_decode: alloc input: %w", err)
	}
	if !mod.Memory().Write(inp, body) {
		return nil, 0, errors.New("magic2_decode: input outside memory")
	}
	outp, err := alloc(cap)
	if err != nil {
		return nil, 0, fmt.Errorf("magic2_decode: alloc output: %w", err)
	}
	v, err := kernel.Call(ctx, uint64(inp), uint64(len(body)), uint64(outp), uint64(cap))
	if err != nil {
		return nil, 0, fmt.Errorf("magic2_decode: %w", err)
	}
	if v[0] == 0 || v[0] > uint64(cap) {
		return nil, 0, fmt.Errorf("magic2_decode: rejected input (returned %d)", v[0])
	}
	out, ok := mod.Memory().Read(outp, uint32(v[0]))
	if !ok {
		return nil, 0, errors.New("magic2_decode: output outside memory")
	}

	// Best-effort input consumption: only ask the guest when the export
	// is present. A missing export or a zero value means the caller has
	// to fall back to the binary-search path; never error on it.
	var consumed uint32
	if cfn := mod.ExportedFunction("magic2_get_input_consumed"); cfn != nil {
		if cv, cerr := cfn.Call(ctx); cerr == nil && cv[0] > 0 && cv[0] <= uint64(len(body)) {
			consumed = uint32(cv[0])
		}
	}
	return append([]byte(nil), out...), consumed, nil
}