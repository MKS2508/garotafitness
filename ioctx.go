package garotafitness

import (
	"context"
	"io"
	"sync"
)

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

type ctxAt struct {
	ctx context.Context
	ra  io.ReaderAt
}

func (c ctxAt) ReadAt(p []byte, off int64) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.ra.ReadAt(p, off)
}

var copyBufs = sync.Pool{New: func() any {
	b := make([]byte, 32<<10)
	return &b
}}

func copyCtx(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	p := copyBufs.Get().(*[]byte)
	defer copyBufs.Put(p)
	return io.CopyBuffer(dst, ctxReader{ctx, src}, *p)
}
