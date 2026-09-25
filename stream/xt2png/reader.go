// Package xt2png restores official XTool XTL0 streams (FreeArc method xt2png).
//
// unpackcmd is `xtool.exe decode -t100p - - <stdin> <stdout>`. Farming Simulator
// 25 uses method png+preflate. PNG restore follows PrecompZLib.pas DecodePNG.
// Preflate restore is official preflate_reencode.
package xt2png

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	codecZLib   = 6 // PrecompZLib in the Codecs insert order
	subPreflate = 2
	subPNG      = 3
	maxBlock    = 512 << 20
	maxTail     = 512 << 20
)

var (
	errNil      = errors.New("xt2png: nil reader")
	errClosed   = errors.New("xt2png: closed")
	errBadMagic = errors.New("xt2png: bad magic")
	errTooLarge = errors.New("xt2png: too large")
	errGuest    = errors.New("xt2png: guest")
	errCodec    = errors.New("xt2png: unsupported stream")
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
	if h.Depth < 0 || h.Depth > 16 {
		return nil, fmt.Errorf("xt2png: depth %d", h.Depth)
	}
	rd := &reader{ctx: ctx, src: br, hdr: h, st: stNeedCount}
	if len(h.Dups) > 0 {
		rd.dd = newDedup(h.Dups)
	}
	return rd, nil
}

type reader struct {
	ctx       context.Context
	src       *bufio.Reader
	hdr       Header
	dd        *dedup
	g         *prefguest
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
			// Shipped xtool DecChunk reads StreamCount directly. Extra
			// EncInit resources are not repeated per chunk.
			sc, err := readI32(r.src)
			if err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					return io.EOF
				}
				return err
			}
			if sc < 0 {
				return io.EOF
			}
			bs, err := readI64(r.src)
			if err != nil {
				return fmt.Errorf("xt2png: blocksize: %w", err)
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
				h, err := readStreamHeader(r.src)
				if err != nil {
					return fmt.Errorf("xt2png: stream header: %w", err)
				}
				r.headers[i] = h
			}
			r.block = make([]byte, bs)
			if bs > 0 {
				if _, err := io.ReadFull(r.src, r.block); err != nil {
					return fmt.Errorf("xt2png: block: %w", err)
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
			n, err := readU32(r.src)
			if err != nil {
				return fmt.Errorf("xt2png: stream tail: %w", err)
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
				return fmt.Errorf("xt2png: stream tail: %w", err)
			}
			r.off = 0
			return nil
		case stNeedRestore:
			h := r.headers[r.si]
			id := r.dd.begin()
			var data []byte
			var err error
			if h.Kind&kindDuplicated == kindDuplicated {
				data, err = r.dd.copy(h.Option)
			} else {
				raw, ext, err2 := r.takeStream(h)
				if err2 != nil {
					return err2
				}
				data, err = r.restore(h, raw, ext)
				if err == nil {
					r.dd.save(id, data)
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
			n, err := readU32(r.src)
			if err != nil {
				return fmt.Errorf("xt2png: tail: %w", err)
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
				return fmt.Errorf("xt2png: tail: %w", err)
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
		return nil, nil, fmt.Errorf("xt2png: stream span %d+%d of %d", r.blockOff, n, len(r.block))
	}
	payload := r.block[r.blockOff : r.blockOff+n]
	r.blockOff += n
	if h.Kind&kindNested == kindNested {
		inner, err := decodeChunk(r.ctx, payload, r.hdr)
		if err != nil {
			return nil, nil, err
		}
		return inner, nil, nil
	}
	if h.Kind&kindExtended == kindExtended {
		if n < 4 {
			return nil, nil, fmt.Errorf("xt2png: extended size")
		}
		extSize := int(int32(le32(payload[n-4:])))
		if extSize < 0 || 4+extSize > n {
			return nil, nil, fmt.Errorf("xt2png: ext %d", extSize)
		}
		rawEnd := n - extSize - 4
		return payload[:rawEnd], payload[rawEnd : rawEnd+extSize], nil
	}
	return payload, nil, nil
}

func unwrapNested(raw []byte) (payload, ext []byte, ok bool) {
	if len(raw) < 8 {
		return nil, nil, false
	}
	n := int(int32(binary.LittleEndian.Uint32(raw[:4])))
	if n < 0 || 4+n+4 > len(raw) {
		return nil, nil, false
	}
	es := int(int32(binary.LittleEndian.Uint32(raw[4+n : 4+n+4])))
	if es < 0 || 4+n+4+es > len(raw) {
		return nil, nil, false
	}
	return raw[4 : 4+n], raw[4+n+4 : 4+n+4+es], true
}

func (r *reader) restore(h streamHeader, raw, ext []byte) ([]byte, error) {
	if h.Kind&kindNested == kindNested {
		if p, e, ok := unwrapNested(raw); ok {
			raw, ext = p, e
		} else if int32(len(raw)) == h.OldSize || h.OldSize == 0 {
			return raw, nil
		}
	}
	sub := getBits(h.Option, 0, 3)
	switch {
	case h.Codec == codecZLib && sub == subPNG, sub == subPNG && containsToken(r.hdr.Method, "png"):
		out, err := decodePNG(raw, int(h.OldSize))
		if err != nil {
			if p := os.Getenv("XT2PNG_DUMP"); p != "" {
				_ = os.WriteFile(p, raw, 0o644)
				_ = os.WriteFile(p+".meta", []byte(fmt.Sprintf("codec=%d opt=%#x kind=%d old=%d new=%d raw=%d\n", h.Codec, uint32(h.Option), h.Kind, h.OldSize, h.NewSize, len(raw))), 0o644)
			}
			return nil, fmt.Errorf("%w codec=%d opt=%#x kind=%d old=%d new=%d raw=%d", err, h.Codec, uint32(h.Option), h.Kind, h.OldSize, h.NewSize, len(raw))
		}
		if h.OldSize > 0 && int32(len(out)) != h.OldSize {
			return nil, fmt.Errorf("xt2png: png got %d want %d", len(out), h.OldSize)
		}
		return out, nil
	case h.Codec == codecZLib && sub == subPreflate, sub == subPreflate && containsToken(r.hdr.Method, "preflate"):
		if err := r.ensureGuest(); err != nil {
			return nil, err
		}
		out, err := r.g.preflate(raw, ext, int(h.OldSize))
		if err != nil {
			return nil, err
		}
		if h.OldSize > 0 && int32(len(out)) != h.OldSize {
			return nil, fmt.Errorf("xt2png: preflate got %d want %d", len(out), h.OldSize)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w codec=%d opt=%#x kind=%d", errCodec, h.Codec, uint32(h.Option), h.Kind)
	}
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

func decodeChunk(ctx context.Context, payload []byte, hdr Header) ([]byte, error) {
	rd := &reader{ctx: ctx, src: bufio.NewReader(bytes.NewReader(payload)), hdr: hdr, st: stNeedCount}
	defer rd.Close()
	return io.ReadAll(rd)
}

func containsToken(s, tok string) bool {
	for i := 0; i+len(tok) <= len(s); i++ {
		if s[i:i+len(tok)] != tok {
			continue
		}
		if i > 0 {
			c := s[i-1]
			if c != '+' && c != ':' && c != ',' {
				continue
			}
		}
		if i+len(tok) < len(s) {
			c := s[i+len(tok)]
			if c != '+' && c != ':' && c != ',' {
				continue
			}
		}
		return true
	}
	return false
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

type dedup struct {
	want  map[int32]int32
	store map[int32][]byte
	next  int32
}

func newDedup(dups []Dup) *dedup {
	d := &dedup{want: make(map[int32]int32, len(dups)), store: make(map[int32][]byte, len(dups))}
	for _, x := range dups {
		if x.Count > 0 {
			d.want[x.Index] = x.Count
		}
	}
	return d
}

func (d *dedup) begin() int32 {
	if d == nil {
		return -1
	}
	id := d.next
	d.next++
	return id
}

func (d *dedup) save(id int32, data []byte) {
	if d == nil || id < 0 {
		return
	}
	if d.want[id] > 0 {
		d.store[id] = append([]byte(nil), data...)
	}
}

func (d *dedup) copy(src int32) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("xt2png: dup without table")
	}
	data, ok := d.store[src]
	if !ok {
		return nil, fmt.Errorf("xt2png: missing dup %d", src)
	}
	d.want[src]--
	if d.want[src] <= 0 {
		delete(d.store, src)
		delete(d.want, src)
	}
	return append([]byte(nil), data...), nil
}
