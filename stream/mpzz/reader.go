// Package mpzz decodes the FitGirl mpzz atom (ProFrager OGGRE).
package mpzz

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
)

// oggre is the inner tag on fg-01 after SREP (SREP keeps unique literals).
const oggre = "OGGRE"

const (
	ver0         = 0x00
	statMask     = 0x07 // books-stat -sX, X in [0,3]
	flagSolidBit = 0x08 // set when solid mode is on (default; -ds clears)
)

// NewReader wraps an OGGRE stream as compress/gzip does.
// Decompression runs in the wasm guest (single-threaded wazero).
func NewReader(ctx context.Context, r io.Reader) (io.ReadCloser, error) {
	if r == nil {
		return nil, errNil
	}
	src, err := slurp(r)
	if err != nil {
		return nil, err
	}
	if _, err := parseHeader(bytes.NewReader(src)); err != nil {
		return nil, err
	}
	return &reader{ctx: ctx, src: src}, nil
}

type header struct {
	ver   uint8
	flags uint8
}

func parseHeader(r io.Reader) (header, error) {
	var b [7]byte
	n, err := io.ReadFull(r, b[:])
	if n >= 5 && string(b[:5]) != oggre {
		return header{}, errMagic
	}
	if err != nil {
		return header{}, err
	}
	h := header{ver: b[5], flags: b[6]}
	if h.ver != ver0 {
		return header{}, fmt.Errorf("mpzz: version %d: %w", h.ver, errVersion)
	}
	if h.flags&statMask > 3 {
		return header{}, fmt.Errorf("mpzz: books-stat %d: %w", h.flags&statMask, errFlags)
	}
	return h, nil
}

// slurp copies r into a buffer. A sized ReaderAt still at offset 0 is
// read with ReadAt so Seek-based streams (bytes.Reader, SectionReader)
// do not depend on the Read cursor.
func slurp(r io.Reader) ([]byte, error) {
	type sizedAt interface {
		io.ReaderAt
		io.Seeker
		Size() int64
	}
	if s, ok := r.(sizedAt); ok {
		off, err := s.Seek(0, io.SeekCurrent)
		if err == nil && off == 0 {
			n := s.Size()
			if n == 0 {
				return nil, io.EOF
			}
			b := make([]byte, n)
			nr, err := s.ReadAt(b, 0)
			if nr != int(n) {
				b = b[:nr]
				if err == nil || err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return b, err
			}
			if err == io.EOF {
				err = nil
			}
			return b, err
		}
	}
	return io.ReadAll(r)
}

type reader struct {
	ctx context.Context
	src []byte
	buf []byte
	off int
	err error
}

func (r *reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil && r.off >= len(r.buf) {
		return 0, r.err
	}
	if r.off >= len(r.buf) {
		if err := r.fill(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

func (r *reader) Close() error {
	r.err = errClosed
	r.buf = nil
	r.src = nil
	return nil
}

func (r *reader) fill() error {
	if len(r.src) == 0 {
		return io.EOF
	}
	out, err := DecodeGuest(r.ctx, r.src, 0)
	r.src = nil
	if err != nil {
		if errors.Is(err, errGuest) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	r.buf = out
	r.off = 0
	return nil
}

// DebugPath is the last OGGRE record kind; tests read it.
var DebugPath string

// DebugIdentN and DebugSerial are the last stream's first 167c0 fields.
var DebugIdentN int
var DebugSerial uint32
var DebugHeaderLeft int
var DebugDestPages int
var DebugFrames [3]int

var (
	errNil     = errors.New("mpzz: nil reader")
	errMagic   = errors.New("mpzz: bad magic")
	errVersion = errors.New("mpzz: bad version")
	errFlags   = errors.New("mpzz: bad flags")
	errClosed  = errors.New("mpzz: closed")
	errGuest   = errors.New("mpzz: guest")
)
