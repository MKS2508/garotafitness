package sevenz

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"

	"github.com/lucasew/garotafitness/internal/wasmrun"
	"github.com/tetratelabs/wazero"
)

//go:embed sevenzenc.wasm
var guest []byte

type lzmaOpts struct {
	dictLog, fb, lc, lp, pb int
	algo, btMode, hashBytes int
	reduce                  uint32
}

func fileOpts(reduce uint32) lzmaOpts {
	// 7-Zip -m0=lzma:x=4 is HC5 (algo 0, 5-byte hash).
	return lzmaOpts{dictLog: 19, fb: 32, lc: 3, lp: 0, pb: 2, algo: 0, btMode: 0, hashBytes: 5, reduce: reduce}
}

func headerOpts() lzmaOpts {
	// 7zHandlerOut.cpp SetHeaderMethod: LZMA BT2, level 5, fb=273, dict=1MiB.
	return lzmaOpts{dictLog: 20, fb: 273, lc: 3, lp: 0, pb: 2, algo: 1, btMode: 1, hashBytes: 2}
}

type lzmaEnc struct{ inst *wasmrun.Instance }

func newLzmaEnc(ctx context.Context) (*lzmaEnc, error) {
	inst, err := wasmrun.Open(ctx, wazero.NewCompilationCache(), guest, "sevenz", wasmrun.Emscripten(nil), nil)
	if err != nil {
		return nil, err
	}
	return &lzmaEnc{inst: inst}, nil
}

func (e *lzmaEnc) Close(ctx context.Context) error {
	if e == nil || e.inst == nil {
		return nil
	}
	err := e.inst.Close(ctx)
	e.inst = nil
	return err
}

func (e *lzmaEnc) encode(ctx context.Context, data []byte, o lzmaOpts) ([]byte, error) {
	n := 36
	if o.reduce != 0 {
		n = 40
	}
	config := make([]byte, n)
	for i, v := range []int{o.dictLog, o.fb, o.lc, o.lp, o.pb, o.algo, o.btMode, o.hashBytes} {
		binary.LittleEndian.PutUint32(config[4*i:], uint32(v))
	}
	if n >= 40 {
		binary.LittleEndian.PutUint32(config[32:], o.reduce)
	}
	capacity := len(data) + len(data)/3 + 65536
	mod := e.inst.Mod
	alloc := func(n int) (uint64, error) {
		v, err := mod.ExportedFunction("malloc").Call(ctx, uint64(max(1, n)))
		if err != nil {
			return 0, err
		}
		if v[0] == 0 {
			return 0, fmt.Errorf("sevenz: allocation failed")
		}
		return v[0], nil
	}
	free := func(p uint64) { _, _ = mod.ExportedFunction("free").Call(ctx, p) }
	src, err := alloc(len(data))
	if err != nil {
		return nil, err
	}
	defer free(src)
	cfg, err := alloc(len(config))
	if err != nil {
		return nil, err
	}
	defer free(cfg)
	outp, err := alloc(capacity)
	if err != nil {
		return nil, err
	}
	defer free(outp)
	if !mod.Memory().Write(uint32(src), data) || !mod.Memory().Write(uint32(cfg), config) {
		return nil, fmt.Errorf("sevenz: input outside memory")
	}
	v, err := mod.ExportedFunction("sevenz_lzma").Call(ctx, src, uint64(len(data)), cfg, uint64(len(config)), outp, uint64(capacity))
	if err != nil {
		return nil, fmt.Errorf("sevenz: %w", err)
	}
	if v[0] == 0 || v[0] > uint64(capacity) {
		return nil, fmt.Errorf("sevenz: rejected input")
	}
	out, ok := mod.Memory().Read(uint32(outp), uint32(v[0]))
	if !ok {
		return nil, fmt.Errorf("sevenz: output outside memory")
	}
	return bytes.Clone(out), nil
}
