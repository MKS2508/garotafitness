package fgpack

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/lucasew/garotafitness/internal/wasmrun"
	"github.com/tetratelabs/wazero"
)

// Encoder keeps one Guest so many small files do not each pay instantiate.
type Encoder struct {
	inst *wasmrun.Instance
}

// NewEncoder compiles the LZMA Guest once.
func NewEncoder(ctx context.Context) (*Encoder, error) {
	inst, err := wasmrun.Open(ctx, wazero.NewCompilationCache(), guest, "fgpack", wasmrun.Emscripten(nil), nil)
	if err != nil {
		return nil, err
	}
	return &Encoder{inst: inst}, nil
}

func (e *Encoder) Close(ctx context.Context) error {
	if e == nil || e.inst == nil {
		return nil
	}
	err := e.inst.Close(ctx)
	e.inst = nil
	return err
}

// Encode compresses one buffer with the given LZMA options.
func (e *Encoder) Encode(ctx context.Context, data []byte, o Options) ([]byte, error) {
	if e == nil || e.inst == nil {
		return nil, fmt.Errorf("fgpack: closed encoder")
	}
	if len(data) > 512<<20 {
		return nil, fmt.Errorf("fgpack: input exceeds memory limit")
	}
	if o.DictLog < 12 || o.DictLog > 29 || o.FastBytes < 5 || o.FastBytes > 273 || o.LC < 0 || o.LC > 8 || o.LP < 0 || o.LP > 4 || o.PB < 0 || o.PB > 4 {
		return nil, fmt.Errorf("fgpack: invalid compression parameters")
	}
	config := encodeConfig(o)
	capacity := len(data) + len(data)/3 + 65536
	mod := e.inst.Mod
	alloc := func(n int) (uint64, error) {
		v, err := mod.ExportedFunction("malloc").Call(ctx, uint64(max(1, n)))
		if err != nil {
			return 0, err
		}
		if v[0] == 0 {
			return 0, fmt.Errorf("fgpack: allocation failed")
		}
		return v[0], nil
	}
	free := func(p uint64) {
		_, _ = mod.ExportedFunction("free").Call(ctx, p)
	}
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
		return nil, fmt.Errorf("fgpack: input outside memory")
	}
	v, err := mod.ExportedFunction("fgpack_encode").Call(ctx, src, uint64(len(data)), cfg, uint64(len(config)), outp, uint64(capacity))
	if err != nil {
		return nil, fmt.Errorf("fgpack: %w", err)
	}
	if v[0] == 0 || v[0] > uint64(capacity) {
		return nil, fmt.Errorf("fgpack: rejected input")
	}
	out, ok := mod.Memory().Read(uint32(outp), uint32(v[0]))
	if !ok {
		return nil, fmt.Errorf("fgpack: output outside memory")
	}
	return bytes.Clone(out), nil
}

func encodeConfig(o Options) []byte {
	n := 20
	if o.Algo != 0 || o.BTMode != 0 || o.HashBytes != 0 || o.ReduceToSize {
		n = 36
	}
	config := make([]byte, n)
	for i, v := range []int{o.DictLog, o.FastBytes, o.LC, o.LP, o.PB} {
		binary.LittleEndian.PutUint32(config[4*i:], uint32(v))
	}
	if n >= 32 {
		hash := o.HashBytes
		if hash == 0 {
			hash = 4
		}
		binary.LittleEndian.PutUint32(config[20:], uint32(o.Algo))
		binary.LittleEndian.PutUint32(config[24:], uint32(o.BTMode))
		binary.LittleEndian.PutUint32(config[28:], uint32(hash))
	}
	return config
}
