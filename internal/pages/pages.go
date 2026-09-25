// Package pages is a pool of fixed-size buffers for extract I/O.
package pages

import (
	"io"
	"sync"
)

// Size is 32KiB so pooled chunks stay in Go's small allocator.
const Size = 32 << 10

var pool = sync.Pool{New: func() any {
	b := make([]byte, Size)
	return &b
}}

// Get returns a page from the pool.
func Get() []byte {
	p := pool.Get().(*[]byte)
	return (*p)[:Size]
}

// Put returns a page to the pool. Other lengths are dropped.
func Put(b []byte) {
	if cap(b) != Size {
		return
	}
	b = b[:Size]
	pool.Put(&b)
}

// Buffer holds n bytes split across pooled pages.
type Buffer struct {
	chunks [][]byte
	n      int64
}

// Read pulls n bytes from r into pooled pages.
func Read(r io.Reader, n int64) (*Buffer, error) {
	if n == 0 {
		return &Buffer{}, nil
	}
	if n < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	buf := &Buffer{}
	left := n
	for left > 0 {
		p := Get()
		chunk := int64(Size)
		if chunk > left {
			chunk = left
		}
		if _, err := io.ReadFull(r, p[:chunk]); err != nil {
			Put(p)
			buf.Release()
			return nil, err
		}
		buf.chunks = append(buf.chunks, p[:chunk])
		buf.n += chunk
		left -= chunk
	}
	return buf, nil
}

// Release returns every page to the pool.
func (b *Buffer) Release() {
	if b == nil {
		return
	}
	for _, p := range b.chunks {
		Put(p)
	}
	b.chunks = nil
	b.n = 0
}

// Reader reads the buffered bytes from the start.
func (b *Buffer) Reader() io.Reader {
	if b == nil {
		return &reader{}
	}
	return &reader{chunks: b.chunks}
}

type reader struct {
	chunks [][]byte
	i, off int
}

func (r *reader) Read(p []byte) (int, error) {
	if r.i >= len(r.chunks) {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[r.i][r.off:])
	r.off += n
	if r.off == len(r.chunks[r.i]) {
		r.i++
		r.off = 0
	}
	return n, nil
}
