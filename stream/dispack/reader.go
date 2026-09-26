// Package dispack decodes the FreeArc DisPack x86 filter.
//
// Container is from third_party/freearc/Compression/DisPack/C_DisPack.cpp
// (DISPACK_METHOD::decompress). Unfilter is DisUnFilter in DisPack.cpp.
// WASM wrap is blocked: repo mise.toml has no wasi-sdk (ADR-0004).
package dispack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/lucasew/garotafitness/internal/chunkbuf"
)

const (
	tagData    = 0xC71B3AE1
	tagEXE     = tagData + 1
	defaultBlk = 8 << 20
	inSlack    = defaultBlk/4 + 1024
	baseStart  = 1 << 30
	baseWrap   = 3 << 30
	baseSub    = 2 << 30
)

// NewReader unwraps a DisPack stream.
func NewReader(r io.Reader) (io.ReadCloser, error) {
	if r == nil {
		return nil, errNilReader
	}
	rd := &reader{src: r, base: baseStart}
	if err := rd.readChunk(); err != nil {
		return nil, err
	}
	return rd, nil
}

type reader struct {
	src   io.Reader
	chunk uint32
	base  uint32
	chunkbuf.Reader
}

func (r *reader) readChunk() error {
	var b [4]byte
	n, err := io.ReadFull(r.src, b[:])
	if n == 0 && (err == io.EOF || err == io.ErrUnexpectedEOF) {
		r.EOF = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("dispack: chunk: %w", err)
	}
	r.chunk = binary.LittleEndian.Uint32(b[:])
	if r.chunk == 0 || r.chunk > defaultBlk {
		return fmt.Errorf("dispack: chunk %d", r.chunk)
	}
	return nil
}

func (r *reader) Read(p []byte) (int, error) {
	return r.Reader.Read(p, r.next)
}

func (r *reader) Close() error {
	return r.Reader.Close(errClosed)
}

func (r *reader) next() ([]byte, error) {
	tag, err := readU32EOF(r.src)
	if err != nil {
		return nil, err
	}
	var out []byte
	switch {
	case !isTag(tag) || tag == tagData:
		var data []byte
		if tag == tagData {
			n, err := readU32(r.src)
			if err != nil {
				return nil, fmt.Errorf("dispack: data len: %w", err)
			}
			if n > r.chunk {
				return nil, fmt.Errorf("dispack: data len %d", n)
			}
			data, err = readExact(r.src, int(n))
			if err != nil {
				return nil, fmt.Errorf("dispack: data: %w", err)
			}
		} else {
			data = make([]byte, r.chunk)
			binary.LittleEndian.PutUint32(data, tag)
			if _, err := io.ReadFull(r.src, data[4:]); err != nil {
				return nil, fmt.Errorf("dispack: data: %w", err)
			}
		}
		out = data
		r.base += uint32(len(out))
	case tag == tagEXE:
		outSize, err := readU32(r.src)
		if err != nil {
			return nil, fmt.Errorf("dispack: exe out: %w", err)
		}
		inSize, err := readU32(r.src)
		if err != nil {
			return nil, fmt.Errorf("dispack: exe in: %w", err)
		}
		if outSize > defaultBlk || inSize > defaultBlk+inSlack {
			return nil, errEXESize
		}
		in, err := readExact(r.src, int(inSize))
		if err != nil {
			return nil, fmt.Errorf("dispack: exe: %w", err)
		}
		out = make([]byte, outSize)
		if !unfilter(in, out, r.base) {
			return nil, errBadFilter
		}
		r.base += outSize
	default:
		return nil, fmt.Errorf("dispack: tag %x", tag)
	}
	if r.base >= baseWrap {
		r.base -= baseSub
	}
	return out, nil
}

func isTag(x uint32) bool {
	return x^tagData < 0x10
}

func readU32EOF(r io.Reader) (uint32, error) {
	var b [4]byte
	n, err := io.ReadFull(r, b[:])
	if n == 0 && (err == io.EOF || err == io.ErrUnexpectedEOF) {
		return 0, io.EOF
	}
	if err != nil {
		return 0, fmt.Errorf("dispack: tag: %w", err)
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func readU32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func readExact(r io.Reader, n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

var (
	errNilReader = errors.New("dispack: nil reader")
	errEXESize   = errors.New("dispack: exe size")
	errBadFilter = errors.New("dispack: bad exe filter")
	errClosed    = errors.New("dispack: closed")
)
