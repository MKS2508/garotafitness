// Package delta decodes the FreeArc Delta table filter.
//
// Stream layout and undiff/unreorder are from
// third_party/freearc/Compression/Delta/Delta.cpp
// (delta_decompress, decode_type, undiff_table, unreorder_table).
// WASM wrap is blocked: repo mise.toml has no wasi-sdk (ADR-0004).
package delta

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/lucasew/garotafitness/internal/chunkbuf"
)

const maxElem = 30

// NewReader unwraps a Delta-preprocessed stream.
func NewReader(r io.Reader) (io.ReadCloser, error) {
	if r == nil {
		return nil, errNilReader
	}
	return &reader{src: r}, nil
}

type reader struct {
	src io.Reader
	chunkbuf.Reader
}

func (r *reader) Read(p []byte) (int, error) {
	return r.Reader.Read(p, r.next)
}

func (r *reader) Close() error {
	return r.Reader.Close(errClosed)
}

func (r *reader) next() ([]byte, error) {
	dataSize, err := readU32EOF(r.src)
	if err != nil {
		return nil, err
	}
	tableSize, err := readU32(r.src)
	if err != nil {
		return nil, fmt.Errorf("delta: tablesize: %w", err)
	}
	if dataSize > 0x7fffffff || tableSize > 0x7fffffff {
		return nil, errTooLarge
	}
	skip, err := readExact(r.src, int(tableSize))
	if err != nil {
		return nil, fmt.Errorf("delta: skip: %w", err)
	}
	typ, err := readExact(r.src, int(tableSize))
	if err != nil {
		return nil, fmt.Errorf("delta: type: %w", err)
	}
	rows, err := readExact(r.src, int(tableSize))
	if err != nil {
		return nil, fmt.Errorf("delta: rows: %w", err)
	}
	data, err := readExact(r.src, int(dataSize))
	if err != nil {
		return nil, fmt.Errorf("delta: data: %w", err)
	}
	nTab := int(tableSize) / 4
	pos := 0
	for i := 0; i < nTab; i++ {
		sk := int(binary.LittleEndian.Uint32(skip[i*4:]))
		t := binary.LittleEndian.Uint32(typ[i*4:])
		nr := int(binary.LittleEndian.Uint32(rows[i*4:]))
		n, doDiff, imm := decodeType(t)
		if n == 0 || n > maxElem {
			return nil, fmt.Errorf("delta: type %d", t)
		}
		if sk < 0 || nr < 0 {
			return nil, errTable
		}
		pos += sk
		need := n * nr
		if pos < 0 || pos > len(data) || need < 0 || pos+need > len(data) {
			return nil, errTable
		}
		tab := data[pos : pos+need]
		unreorder(n, tab, nr, imm)
		undiff(n, tab, nr, doDiff)
		pos += need
	}
	return data, nil
}

func decodeType(typ uint32) (n int, doDiff, immutable []bool) {
	for typ > 1 {
		immutable = append(immutable, typ&1 == 1)
		doDiff = append(doDiff, typ&1 == 0)
		typ >>= 1
	}
	return len(immutable), doDiff, immutable
}

func undiff(n int, table []byte, rows int, doDiff []bool) {
	for r := n; r < n*rows; r += n {
		carry := 0
		for i := 0; i < n; i++ {
			if doDiff[i] {
				sum := int(table[r+i]) + int(table[r+i-n]) + carry
				table[r+i] = byte(sum)
				carry = sum / 256
			} else {
				carry = 0
			}
		}
	}
}

func unreorder(n int, table []byte, rows int, immutable []bool) {
	imm := 0
	for _, v := range immutable {
		if v {
			imm++
		}
	}
	if imm == 0 || imm == n {
		return
	}
	tmp := make([]byte, n*rows)
	copy(tmp, table)
	p, q, q1 := 0, 0, imm*rows
	for i := 0; i < rows; i++ {
		for k := 0; k < n; k++ {
			if immutable[k] {
				table[p] = tmp[q]
				q++
			} else {
				table[p] = tmp[q1]
				q1++
			}
			p++
		}
	}
}

func readU32EOF(r io.Reader) (uint32, error) {
	var b [4]byte
	n, err := io.ReadFull(r, b[:])
	if n == 0 && (err == io.EOF || err == io.ErrUnexpectedEOF) {
		return 0, io.EOF
	}
	if err != nil {
		return 0, fmt.Errorf("delta: datasize: %w", err)
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
	errNilReader = errors.New("delta: nil reader")
	errTooLarge  = errors.New("delta: block too large")
	errTable     = errors.New("delta: table overruns data")
	errClosed    = errors.New("delta: closed")
)
