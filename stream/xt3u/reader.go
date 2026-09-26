// Package xt3u restores official XTool XTL0 streams (FreeArc method xt3u).
//
// unpackcmd is `xtool.exe decode -t100p - - <stdin> <stdout>`. The container
// is PrecompMain.pas Decode/DecInit/DecChunk (XTOOL_PRECOMP). fg-03 uses
// method unity:lz4hc:l12; Unity Scan1 (xtool-plugins/unity engine/unity.dpr)
// only locates streams. Restore is LZ4Restore in PrecompLZ4.pas.
package xt3u

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/lucasew/garotafitness/internal/xtl"
)

const (
	codecLZ4 = 7 // PrecompLZ4 in the hardcoded Codecs array
	maxBlock = 512 << 20
	maxTail  = 64 << 20
)

var (
	errNil      = errors.New("xt3u: nil reader")
	errClosed   = errors.New("xt3u: closed")
	errBadMagic = errors.New("xt3u: bad magic")
	errTooLarge = errors.New("xt3u: too large")
	errGuest    = errors.New("xt3u: guest")
	errCodec    = errors.New("xt3u: unsupported stream")
)

const (
	stNeedCount = iota
	stNeedStream
	stNeedRestore
	stNeedFinal
)

// NewReader wraps an official XTL0 stream as compress/gzip does.
func NewReader(ctx context.Context, r io.Reader) (io.ReadCloser, error) {
	if r == nil {
		return nil, errNil
	}
	br := bufio.NewReader(r)
	h, err := parseHeader(br)
	if err != nil {
		return nil, err
	}
	if h.Compressed != 0 {
		return nil, fmt.Errorf("xt3u: compressed=%d", h.Compressed)
	}
	if h.StoreDD > 0 {
		return nil, fmt.Errorf("xt3u: srep wrap storeDD=%d", h.StoreDD)
	}
	if h.Depth < 0 || h.Depth > 16 {
		return nil, fmt.Errorf("xt3u: depth %d", h.Depth)
	}
	rd := &reader{ctx: ctx, src: br, hdr: h, st: stNeedCount}
	if h.StoreDD > -2 {
		rd.dd = xtl.NewDedup(h.Dups)
	}
	return rd, nil
}

type reader struct {
	ctx       context.Context
	src       *bufio.Reader
	hdr       Header
	dd        *xtl.Dedup
	g         *lz4guest
	headers   []streamHeader
	block     []byte
	blockOff  int
	si        int
	st        int
	streamIdx int32
	out       []byte
	off       int
	err       error
	eof       bool
}

func (r *reader) Read(p []byte) (int, error) {
	if r.err != nil && r.off >= len(r.out) {
		return 0, r.err
	}
	for r.off >= len(r.out) {
		if r.eof {
			return 0, io.EOF
		}
		if err := r.next(); err != nil {
			if err == io.EOF {
				r.eof = true
				r.err = io.EOF
				return 0, io.EOF
			}
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.out[r.off:])
	r.off += n
	return n, nil
}

func (r *reader) Close() error {
	r.err = errClosed
	r.out = nil
	if r.g != nil {
		_ = r.g.Close()
		r.g = nil
	}
	return nil
}

func (r *reader) next() error {
	for {
		switch r.st {
		case stNeedCount:
			if _, err := xtl.ReadResources(r.src, errTooLarge); err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					return io.EOF
				}
				return fmt.Errorf("xt3u: chunk resources: %w", err)
			}
			sc, err := xtl.I32(r.src)
			if err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					return io.EOF
				}
				return err
			}
			if sc < 0 {
				return io.EOF
			}
			bs, err := xtl.I64(r.src)
			if err != nil {
				return fmt.Errorf("xt3u: blocksize: %w", err)
			}
			if sc == 0 {
				r.headers = nil
				r.block = nil
				r.st = stNeedFinal
				continue
			}
			if sc > 1<<20 || bs < 0 || bs > maxBlock {
				return errTooLarge
			}
			r.headers = make([]streamHeader, sc)
			for i := range r.headers {
				h, err := xtl.ReadStreamHeader(r.src)
				if err != nil {
					return fmt.Errorf("xt3u: stream header: %w", err)
				}
				r.headers[i] = h
			}
			r.block = make([]byte, bs)
			if bs > 0 {
				if _, err := io.ReadFull(r.src, r.block); err != nil {
					return fmt.Errorf("xt3u: block: %w", err)
				}
			}
			r.blockOff = 0
			r.si = 0
			r.st = stNeedStream
		case stNeedStream:
			if r.si >= len(r.headers) {
				r.st = stNeedFinal
				continue
			}
			n, err := xtl.U32(r.src)
			if err != nil {
				return fmt.Errorf("xt3u: stream tail: %w", err)
			}
			if n > maxTail {
				return errTooLarge
			}
			r.st = stNeedRestore
			if n == 0 {
				continue
			}
			r.out = make([]byte, n)
			if _, err := io.ReadFull(r.src, r.out); err != nil {
				return fmt.Errorf("xt3u: stream tail: %w", err)
			}
			r.off = 0
			return nil
		case stNeedRestore:
			h := r.headers[r.si]
			id := r.dd.Begin()
			var data []byte
			var err error
			if h.Kind&kindDuplicated == kindDuplicated {
				data, err = xtl.CopyDup(r.dd, "xt3u", h.Option)
			} else {
				raw, ext, err2 := r.takeStream(h)
				if err2 != nil {
					return err2
				}
				data, err = r.restore(h, raw, ext)
				if err == nil {
					r.dd.Save(id, data)
				}
			}
			r.si++
			r.st = stNeedStream
			if err != nil {
				return err
			}
			r.out = data
			r.off = 0
			if len(r.out) == 0 {
				continue
			}
			return nil
		case stNeedFinal:
			n, err := xtl.U32(r.src)
			if err != nil {
				return fmt.Errorf("xt3u: tail: %w", err)
			}
			if n > maxTail {
				return errTooLarge
			}
			r.st = stNeedCount
			if n == 0 {
				continue
			}
			r.out = make([]byte, n)
			if _, err := io.ReadFull(r.src, r.out); err != nil {
				return fmt.Errorf("xt3u: tail: %w", err)
			}
			r.off = 0
			return nil
		default:
			return errClosed
		}
	}
}

func (r *reader) takeStream(h streamHeader) (raw, ext []byte, err error) {
	n := int(h.NewSize)
	if n < 0 || r.blockOff+n > len(r.block) {
		return nil, nil, fmt.Errorf("xt3u: stream span %d+%d of %d", r.blockOff, n, len(r.block))
	}
	payload := r.block[r.blockOff : r.blockOff+n]
	r.blockOff += n
	if h.Kind&kindNested == kindNested {
		return nil, nil, fmt.Errorf("xt3u: nested stream")
	}
	if h.Kind&kindExtended == kindExtended {
		if n < 4 {
			return nil, nil, fmt.Errorf("xt3u: extended size")
		}
		extSize := int(int32(xtl.U32LE(payload[n-4:])))
		if extSize < 0 || 4+extSize > n {
			return nil, nil, fmt.Errorf("xt3u: ext %d", extSize)
		}
		rawEnd := n - extSize - 4
		return payload[:rawEnd], payload[rawEnd : rawEnd+extSize], nil
	}
	return payload, nil, nil
}

func (r *reader) restore(h streamHeader, raw, ext []byte) ([]byte, error) {
	sub := xtl.Bits(h.Option, 0, 3)
	patched := xtl.Bits(h.Option, 31, 1) == 1 || len(ext) > 0
	switch {
	case h.Codec == codecLZ4 && sub == 1, sub == 1 && isLZ4Method(r.hdr.Method):
		level := xtl.Bits(h.Option, 3, 4)
		blk := xtl.Bits(h.Option, 15, 13)
		if blk != 0 {
			return nil, fmt.Errorf("xt3u: lz4hc block %d", blk)
		}
		if err := r.ensureGuest(); err != nil {
			return nil, err
		}
		bound, err := r.g.compressBound(len(raw))
		if err != nil {
			return nil, err
		}
		out, err := r.g.compressHC(raw, level, bound)
		if err != nil {
			return nil, err
		}
		if patched {
			got, err := r.applyPatch(out, ext, int(h.OldSize))
			if err != nil {
				return nil, fmt.Errorf("xt3u: patch kind=%d old=%d new=%d ext=%d raw=%d hc=%d: %w",
					h.Kind, h.OldSize, h.NewSize, len(ext), len(raw), len(out), err)
			}
			return got, nil
		}
		if int32(len(out)) != h.OldSize {
			return nil, fmt.Errorf("xt3u: lz4hc got %d want %d", len(out), h.OldSize)
		}
		return out, nil
	case h.Codec == codecLZ4 && sub == 0:
		accel := xtl.Bits(h.Option, 7, 7)
		blk := xtl.Bits(h.Option, 15, 13)
		if blk != 0 {
			return nil, fmt.Errorf("xt3u: lz4 block %d", blk)
		}
		if err := r.ensureGuest(); err != nil {
			return nil, err
		}
		bound, err := r.g.compressBound(len(raw))
		if err != nil {
			return nil, err
		}
		out, err := r.g.compressFast(raw, accel, bound)
		if err != nil {
			return nil, err
		}
		if patched {
			return r.applyPatch(out, ext, int(h.OldSize))
		}
		if int32(len(out)) != h.OldSize {
			return nil, fmt.Errorf("xt3u: lz4 got %d want %d", len(out), h.OldSize)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w codec=%d opt=%#x kind=%d", errCodec, h.Codec, uint32(h.Option), h.Kind)
	}
}

func (r *reader) applyPatch(prefix, patch []byte, want int) ([]byte, error) {
	if err := r.ensureGuest(); err != nil {
		return nil, err
	}
	if want <= 0 {
		return nil, fmt.Errorf("xt3u: patch size %d", want)
	}
	out, err := r.g.decodePrefix(patch, prefix, want, windowLog(len(prefix)))
	if err != nil {
		return nil, fmt.Errorf("xt3u: patch: %w", err)
	}
	if len(out) != want {
		return nil, fmt.Errorf("xt3u: patch got %d want %d", len(out), want)
	}
	return out, nil
}

func windowLog(prefix int) int {
	if prefix <= 0 {
		return 0
	}
	v := uint64(prefix) >> 1
	n := 0
	for v != 0 {
		v >>= 1
		n++
	}
	return n + 1
}

func (r *reader) ensureGuest() error {
	if r.g != nil {
		return nil
	}
	g, err := openGuest(r.ctx)
	if err != nil {
		return err
	}
	r.g = g
	return nil
}

func isLZ4Method(m string) bool {
	return xtl.ContainsToken(m, "lz4hc") || xtl.ContainsToken(m, "lz4")
}
