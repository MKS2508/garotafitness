package mpzz

import (
	"context"
	_ "embed"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/lucasew/garotafitness/internal/wasmrun"
	"github.com/tetratelabs/wazero"
)

//go:embed mpzzdec.wasm
var guestWASM []byte

var (
	guestCache = sync.OnceValue(wazero.NewCompilationCache)
	guestID    atomic.Uint64
)

// DecodeGuest runs the reconstructed OGGRE wasm kernel on one stream.
func DecodeGuest(ctx context.Context, src []byte, dstCap int) ([]byte, error) {
	if len(guestWASM) == 0 || len(src) == 0 {
		return nil, errGuest
	}
	if dstCap < len(src)*2 {
		dstCap = len(src) * 2
	}
	if dstCap < 64<<20 {
		dstCap = 64 << 20
	}
	if dstCap > 1<<30 {
		dstCap = 1 << 30
	}
	inst, err := wasmrun.Open(ctx, guestCache(), guestWASM, "mpzz", wasmrun.Emscripten(nil), wazero.NewModuleConfig().
		WithName(fmt.Sprintf("mpzz-%d", guestID.Add(1))))
	if err != nil {
		return nil, err
	}
	defer inst.Close(ctx)
	mod := inst.Mod
	mem := mod.Memory()
	fn := mod.ExportedFunction("mpzz_decode")
	malloc := mod.ExportedFunction("malloc")
	free := mod.ExportedFunction("free")
	if mem == nil || fn == nil || malloc == nil || free == nil {
		return nil, errGuest
	}
	alloc := func(n int) (uint32, error) {
		if n <= 0 {
			n = 1
		}
		v, err := malloc.Call(ctx, uint64(uint32(n)))
		if err != nil || len(v) == 0 || v[0] == 0 {
			return 0, errGuest
		}
		return uint32(v[0]), nil
	}
	sp, err := alloc(len(src))
	if err != nil {
		return nil, err
	}
	dp, err := alloc(dstCap)
	if err != nil {
		return nil, err
	}
	if !mem.Write(sp, src) {
		return nil, errGuest
	}
	v, err := fn.Call(ctx, uint64(sp), uint64(uint32(len(src))), uint64(dp), uint64(uint32(dstCap)))
	if err != nil {
		return nil, fmt.Errorf("mpzz: guest: %w", err)
	}
	if len(v) == 0 {
		return nil, errGuest
	}
	if int32(v[0]) == -2 {
		if dstCap >= 1<<30 {
			return nil, fmt.Errorf("%w: dest too small", errGuest)
		}
		return DecodeGuest(ctx, src, dstCap*2)
	}
	if int32(v[0]) <= 0 {
		return nil, fmt.Errorf("%w: decode %d", errGuest, int32(v[0]))
	}
	n := int(int32(v[0]))
	out, ok := mem.Read(dp, uint32(n))
	if !ok {
		return nil, errGuest
	}
	_, _ = free.Call(ctx, uint64(sp))
	_, _ = free.Call(ctx, uint64(dp))
	return append([]byte(nil), out...), nil
}
