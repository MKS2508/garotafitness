package xdelta

import (
	"context"
	"fmt"
	"io"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// ApplyStream decodes a VCDIFF patch with host pread/pwrite so the source and
// target can exceed wasm32 linear memory (FitGirl DLC packs are multi-GiB).
func ApplyStream(ctx context.Context, old io.ReaderAt, oldSize int64, diff io.ReaderAt, diffSize int64, out io.WriterAt) error {
	if diffSize <= 0 {
		return fmt.Errorf("xdelta: empty patch")
	}
	if oldSize < 0 {
		oldSize = 0
	}
	inputs := []struct {
		r io.ReaderAt
		n int64
	}{{old, oldSize}, {diff, diffSize}}
	var mod api.Module
	pread := func(id, posLo, posHi, buf, n uint32) uint32 {
		if int(id) >= len(inputs) || mod == nil || inputs[id].r == nil {
			return 0
		}
		pos := int64(uint64(posLo) | uint64(posHi)<<32)
		if pos < 0 || pos > inputs[id].n {
			return 0
		}
		want := int64(n)
		if left := inputs[id].n - pos; want > left {
			want = left
		}
		if want <= 0 {
			return 0
		}
		tmp := make([]byte, want)
		got, err := inputs[id].r.ReadAt(tmp, pos)
		if got == 0 && err != nil && err != io.EOF {
			return 0
		}
		if !mod.Memory().Write(buf, tmp[:got]) {
			return 0
		}
		return uint32(got)
	}
	pwrite := func(id, posLo, posHi, buf, n uint32) uint32 {
		if id != 2 || mod == nil {
			return 0
		}
		pos := int64(uint64(posLo) | uint64(posHi)<<32)
		src, ok := mod.Memory().Read(buf, n)
		if !ok {
			return 0
		}
		got, err := out.WriteAt(src, pos)
		if err != nil {
			return 0
		}
		return uint32(got)
	}
	sizeLo := func(id uint32) uint32 {
		switch id {
		case 0:
			return uint32(oldSize)
		case 1:
			return uint32(diffSize)
		default:
			return 0
		}
	}
	sizeHi := func(id uint32) uint32 {
		switch id {
		case 0:
			return uint32(uint64(oldSize) >> 32)
		case 1:
			return uint32(uint64(diffSize) >> 32)
		default:
			return 0
		}
	}

	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer rt.Close(context.WithoutCancel(ctx))
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		return fmt.Errorf("xdelta: wasi: %w", err)
	}
	if _, err := rt.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(func(uint32) {}).Export("emscripten_notify_memory_growth").
		NewFunctionBuilder().WithFunc(pread).Export("host_pread").
		NewFunctionBuilder().WithFunc(pwrite).Export("host_pwrite").
		NewFunctionBuilder().WithFunc(sizeLo).Export("host_size_lo").
		NewFunctionBuilder().WithFunc(sizeHi).Export("host_size_hi").
		Instantiate(ctx); err != nil {
		return fmt.Errorf("xdelta: env: %w", err)
	}
	mod, err := rt.InstantiateWithConfig(ctx, guest, wazero.NewModuleConfig().WithStartFunctions("_initialize"))
	if err != nil {
		return fmt.Errorf("xdelta: instantiate: %w", err)
	}
	res, err := mod.ExportedFunction("xdelta_apply_stream").Call(ctx)
	if err != nil {
		return fmt.Errorf("xdelta: apply: %w", err)
	}
	if len(res) == 0 || res[0] != 1 {
		return fmt.Errorf("xdelta: rejected input")
	}
	return nil
}

// SeqWriter turns an append-only Writer into a WriterAt for ApplyStream.
func SeqWriter(w io.Writer) *SeqWriterAt {
	return &SeqWriterAt{w: w}
}

// SeqWriterAt records the number of bytes written.
type SeqWriterAt struct {
	w   io.Writer
	off int64
}

func (s *SeqWriterAt) Size() int64 { return s.off }

func (s *SeqWriterAt) WriteAt(p []byte, pos int64) (int, error) {
	if pos != s.off {
		return 0, fmt.Errorf("xdelta: non-sequential write at %d want %d", pos, s.off)
	}
	n, err := s.w.Write(p)
	s.off += int64(n)
	return n, err
}
