// Package chunkbuf is the pull loop shared by filters that emit one block at a time.
package chunkbuf

import "io"

// Reader holds the unread tail of the last block.
type Reader struct {
	Buf []byte
	Off int
	Err error
	EOF bool
}

// Read copies from the current block, pulling the next one when it is spent.
func (r *Reader) Read(p []byte, next func() ([]byte, error)) (int, error) {
	if r.Err != nil && r.Off >= len(r.Buf) {
		return 0, r.Err
	}
	for r.Off >= len(r.Buf) {
		if r.EOF {
			return 0, io.EOF
		}
		block, err := next()
		if err == io.EOF {
			r.EOF = true
			return 0, io.EOF
		}
		if err != nil {
			r.Err = err
			return 0, err
		}
		r.Buf = block
		r.Off = 0
	}
	n := copy(p, r.Buf[r.Off:])
	r.Off += n
	return n, nil
}

// Close records err and drops the buffer.
func (r *Reader) Close(err error) error {
	r.Err = err
	r.Buf = nil
	return nil
}
