package xt2png

import (
	"context"
	_ "embed"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/lucasew/garotafitness/internal/wasmrun"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed xt2pngdec.wasm
var guestWASM []byte

var instID atomic.Uint64

var compileCache = sync.OnceValue(wazero.NewCompilationCache)

type prefguest struct {
	ctx    context.Context
	inst   *wasmrun.Instance
	mem    api.Memory
	fn     api.Function
	malloc api.Function
	free   api.Function
}

func openGuest(ctx context.Context) (*prefguest, error) {
	if len(guestWASM) == 0 {
		return nil, errGuest
	}
	inst, err := wasmrun.Open(ctx, compileCache(), guestWASM, "xt2png", wasmrun.Emscripten(nil), wazero.NewModuleConfig().
		WithName(fmt.Sprintf("xt2png-%d", instID.Add(1))))
	if err != nil {
		return nil, err
	}
	mod := inst.Mod
	g := &prefguest{
		ctx:    ctx,
		inst:   inst,
		mem:    mod.Memory(),
		fn:     mod.ExportedFunction("xt2png_preflate"),
		malloc: mod.ExportedFunction("malloc"),
		free:   mod.ExportedFunction("free"),
	}
	if g.mem == nil || g.fn == nil || g.malloc == nil || g.free == nil {
		inst.Close(ctx)
		return nil, errGuest
	}
	return g, nil
}

func (g *prefguest) Close() error {
	if g == nil || g.inst == nil {
		return nil
	}
	err := g.inst.Close(g.ctx)
	g.inst = nil
	return err
}

func (g *prefguest) preflate(raw, diff []byte, dstCap int) ([]byte, error) {
	if dstCap <= 0 {
		dstCap = len(raw) + len(diff) + 64
	}
	rp, err := g.alloc(len(raw))
	if err != nil {
		return nil, err
	}
	defer g.dealloc(rp)
	dp, err := g.alloc(max(len(diff), 1))
	if err != nil {
		return nil, err
	}
	defer g.dealloc(dp)
	op, err := g.alloc(dstCap)
	if err != nil {
		return nil, err
	}
	defer g.dealloc(op)
	if len(raw) > 0 && !g.mem.Write(rp, raw) {
		return nil, errGuest
	}
	if len(diff) > 0 && !g.mem.Write(dp, diff) {
		return nil, errGuest
	}
	v, err := g.fn.Call(g.ctx, uint64(rp), uint64(uint32(len(raw))), uint64(dp), uint64(uint32(len(diff))), uint64(op), uint64(uint32(dstCap)))
	if err != nil {
		return nil, fmt.Errorf("xt2png: preflate: %w", err)
	}
	if len(v) == 0 || int32(v[0]) <= 0 {
		return nil, fmt.Errorf("%w: preflate %d", errGuest, int32(v[0]))
	}
	n := int(int32(v[0]))
	out, ok := g.mem.Read(op, uint32(n))
	if !ok {
		return nil, errGuest
	}
	return append([]byte(nil), out...), nil
}

func (g *prefguest) alloc(n int) (uint32, error) {
	if n <= 0 {
		n = 1
	}
	v, err := g.malloc.Call(g.ctx, uint64(uint32(n)))
	if err != nil {
		return 0, fmt.Errorf("xt2png: malloc: %w", err)
	}
	if len(v) == 0 || v[0] == 0 {
		return 0, errGuest
	}
	return uint32(v[0]), nil
}

func (g *prefguest) dealloc(p uint32) {
	if p == 0 {
		return
	}
	_, _ = g.free.Call(g.ctx, uint64(p))
}
