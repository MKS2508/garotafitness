package x5n

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lucasew/garotafitness/internal/scratch"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed hpatchsf.wasm
var guest []byte

// Apply reconstructs new files from old files and an HDIFF19 directory patch.
func Apply(ctx context.Context, oldFiles map[string][]byte, diff []byte) (map[string][]byte, error) {
	info, err := Parse(diff)
	if err != nil {
		return nil, err
	}
	var old bytes.Buffer
	old.Grow(int(info.OldRefSize))
	for _, idx := range info.OldRefs {
		if idx < 0 || idx >= len(info.OldPaths) {
			return nil, fmt.Errorf("x5n: old ref %d", idx)
		}
		name := info.OldPaths[idx]
		if isDirPath(name) {
			return nil, fmt.Errorf("x5n: old ref is a directory %q", name)
		}
		b, ok := oldFiles[name]
		if !ok {
			return nil, fmt.Errorf("x5n: missing old file %s", name)
		}
		old.Write(b)
	}
	if uint64(old.Len()) != info.OldRefSize {
		return nil, fmt.Errorf("x5n: old refs %d want %d", old.Len(), info.OldRefSize)
	}
	plain, err := applySF20(ctx, old.Bytes(), info.Inner)
	if err != nil {
		return nil, err
	}
	if uint64(len(plain)) != info.NewRefSize {
		return nil, fmt.Errorf("x5n: new refs %d want %d", len(plain), info.NewRefSize)
	}
	out := map[string][]byte{}
	off := 0
	for i, idx := range info.NewRefs {
		if idx < 0 || idx >= len(info.NewPaths) {
			return nil, fmt.Errorf("x5n: new ref %d", idx)
		}
		name := info.NewPaths[idx]
		n := int(info.NewRefSizes[i])
		if isDirPath(name) || n < 0 || off+n > len(plain) {
			return nil, fmt.Errorf("x5n: new file %q", name)
		}
		out[name] = bytes.Clone(plain[off : off+n])
		off += n
	}
	if off != len(plain) {
		return nil, fmt.Errorf("x5n: new file sizes %d want %d", off, len(plain))
	}
	return out, nil
}

func applySF20(ctx context.Context, old, diff []byte) ([]byte, error) {
	dir, err := scratch.MkdirTemp(ctx, "x5n-")
	if err != nil {
		return nil, fmt.Errorf("x5n: temp: %w", err)
	}
	defer dir.Close()
	p := lewpath.New("new")
	f, err := p.Create(dir.Root())
	if err != nil {
		return nil, fmt.Errorf("x5n: temp: %w", err)
	}
	newf, ok := f.(interface {
		io.Reader
		io.WriterAt
		io.Seeker
		io.Closer
	})
	if !ok {
		f.Close()
		return nil, fmt.Errorf("x5n: temp: no random access")
	}
	defer newf.Close()

	inputs := [][]byte{old, diff}
	var mod api.Module
	pread := func(id, posLo, posHi, buf, n uint32) uint32 {
		if int(id) >= len(inputs) || mod == nil {
			return 0
		}
		pos := uint64(posLo) | uint64(posHi)<<32
		src := inputs[id]
		if pos > uint64(len(src)) {
			return 0
		}
		chunk := src[pos:]
		if uint64(len(chunk)) > uint64(n) {
			chunk = chunk[:n]
		}
		if !mod.Memory().Write(buf, chunk) {
			return 0
		}
		return uint32(len(chunk))
	}
	pwrite := func(id, posLo, posHi, buf, n uint32) uint32 {
		if id != 2 || mod == nil {
			return 0
		}
		pos := uint64(posLo) | uint64(posHi)<<32
		src, ok := mod.Memory().Read(buf, n)
		if !ok {
			return 0
		}
		got, err := newf.WriteAt(src, int64(pos))
		if err != nil {
			return 0
		}
		return uint32(got)
	}
	sizeLo := func(id uint32) uint32 {
		switch id {
		case 0:
			return uint32(len(old))
		case 1:
			return uint32(len(diff))
		default:
			return 0
		}
	}
	sizeHi := func(id uint32) uint32 {
		switch id {
		case 0:
			return uint32(uint64(len(old)) >> 32)
		case 1:
			return uint32(uint64(len(diff)) >> 32)
		default:
			return 0
		}
	}

	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer rt.Close(context.WithoutCancel(ctx))
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		return nil, fmt.Errorf("x5n: wasi: %w", err)
	}
	if _, err := rt.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(func(uint32) {}).Export("emscripten_notify_memory_growth").
		NewFunctionBuilder().WithFunc(pread).Export("host_pread").
		NewFunctionBuilder().WithFunc(pwrite).Export("host_pwrite").
		NewFunctionBuilder().WithFunc(sizeLo).Export("host_size_lo").
		NewFunctionBuilder().WithFunc(sizeHi).Export("host_size_hi").
		Instantiate(ctx); err != nil {
		return nil, fmt.Errorf("x5n: env: %w", err)
	}
	mod, err = rt.InstantiateWithConfig(ctx, guest, wazero.NewModuleConfig().WithStartFunctions("_initialize"))
	if err != nil {
		return nil, fmt.Errorf("x5n: instantiate: %w", err)
	}
	res, err := mod.ExportedFunction("hpatch_sf20").Call(ctx, 64<<20)
	if err != nil {
		return nil, fmt.Errorf("x5n: apply: %w", err)
	}
	if res[0] != 1 {
		return nil, fmt.Errorf("x5n: corrupt HDIFFSF20 patch")
	}
	if _, err := newf.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("x5n: rewind: %w", err)
	}
	out, err := io.ReadAll(newf)
	if err != nil {
		return nil, fmt.Errorf("x5n: read new: %w", err)
	}
	return out, nil
}
