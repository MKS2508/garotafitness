// Package magic2 decodes LOLZ v22c4b streams using reconstructed Go code.
package magic2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	errNil       = errors.New("magic2: nil reader")
	errClosed    = errors.New("magic2: closed")
	errBitstream = errors.New("magic2: invalid bitstream")
)

func NewReader(src io.Reader) (io.ReadCloser, error) {
	if src == nil {
		return nil, errNil
	}
	h, err := ParseHeader(src)
	if err != nil {
		return nil, err
	}
	if h.LongDistance || h.ROLZ || !h.Mixed || h.LiteralMode != 0 || h.ColorMode > 3 || h.AlphaMode > 4 || h.ImageMode != 0 {
		return nil, fmt.Errorf("magic2: unsupported decoder options %+v", h)
	}
	return &reader{src: src, decoder: newDecoder(h)}, nil
}

type reader struct {
	src      io.Reader
	decoder  *decoder
	metadata *metadata
	chunks   chunkReader
	buf      []byte
	err      error
}

func (r *reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.buf) == 0 && r.err == nil {
		r.err = r.fill()
	}
	if len(r.buf) == 0 {
		return 0, r.err
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}
func (r *reader) Close() error {
	r.src = nil
	r.decoder = nil
	r.metadata = nil
	r.buf = nil
	r.err = errClosed
	return nil
}
func read32(r io.Reader) (uint32, error) {
	var b [4]byte
	_, err := readRequired(r, b[:])
	return binary.LittleEndian.Uint32(b[:]), err
}
func (r *reader) fill() error {
	if r.metadata == nil {
		var b [2]byte
		if _, err := readRequired(r.src, b[:]); err != nil {
			return err
		}
		capacity := uint32(binary.LittleEndian.Uint16(b[:])) << 16
		n, err := read32(r.src)
		if err != nil {
			return err
		}
		if capacity == 0 || n < 4 || n > 16<<20 {
			return fmt.Errorf("%w: metadata capacity=%d n=%d", errBitstream, capacity, n)
		}
		data := make([]byte, n)
		if _, err := readRequired(r.src, data); err != nil {
			return err
		}
		r.metadata = newMetadata(data)
		r.chunks = chunkReader{src: r.src, capacity: capacity}
	}
	s, err := r.metadata.next()
	if err != nil {
		return err
	}
	if s.option == 63 && s.size == 0 {
		if err := r.metadata.r.finish(); err != nil {
			return err
		}
		if r.chunks.remaining != 0 {
			return fmt.Errorf("%w: trailer leftover %d", errBitstream, r.chunks.remaining)
		}
		n, err := read32(r.src)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.EOF
		}
		// Independent workers concatenate another metadata+segment run.
		// Official single-stream files write a 0 word here.
		if n < 4 || n > 16<<20 {
			return fmt.Errorf("%w: next frame n=%d", errBitstream, n)
		}
		data := make([]byte, n)
		if _, err := readRequired(r.src, data); err != nil {
			return err
		}
		r.metadata = newMetadata(data)
		r.chunks.remaining = 0
		if r.decoder.header.Independent {
			r.decoder = newDecoder(r.decoder.header)
		}
		return r.fill()
	}
	if s.size == 0 || s.size > 512<<20 || s.packed == 0 || s.packed > 512<<20 {
		return fmt.Errorf("%w: segment option=%d size=%d packed=%d aux=%d", errBitstream, s.option, s.size, s.packed, s.aux)
	}
	data := make([]byte, s.packed)
	if _, err := readRequired(&r.chunks, data); err != nil {
		return err
	}
	start := len(r.decoder.out)
	if err := r.decoder.decode(data, s); err != nil {
		return fmt.Errorf("magic2: segment at %d (option %d, size %d, aux %d): %w", start, s.option, s.size, s.aux, err)
	}
	r.buf = append([]byte(nil), r.decoder.out[start:]...)
	r.decoder.slide()
	return nil
}

type chunkReader struct {
	src                 io.Reader
	capacity, remaining uint32
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		n, err := read32(r.src)
		if err != nil {
			return 0, err
		}
		if n == 0 || n > r.capacity {
			return 0, fmt.Errorf("%w: chunk n=%d capacity=%d", errBitstream, n, r.capacity)
		}
		r.remaining = n
	}
	if uint64(len(p)) > uint64(r.remaining) {
		p = p[:r.remaining]
	}
	n, err := r.src.Read(p)
	r.remaining -= uint32(n)
	return n, err
}

func readRequired(r io.Reader, p []byte) (int, error) {
	n, err := io.ReadFull(r, p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
