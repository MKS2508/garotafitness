// Package xtl holds XTL0 framing helpers shared by the xt3u and xt2png decoders.
package xtl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Magic is XTOOL_PRECOMP in PrecompMain.pas ($304C5458).
const Magic = "XTL0"

var (
	errDupWithoutTable = errors.New("dup without table")
	errMissingDup      = errors.New("missing dup")
)

const (
	KindDefault    = 0
	KindExtended   = 1
	KindNested     = 2
	KindDuplicated = 4
)

const StreamHeaderSize = 18

// Resource is one named blob written by EncInit.
type Resource struct {
	Name string
	Data []byte
}

// Dup is TDuplicate2: first-seen stream index and extra copy count.
type Dup struct {
	Index int32
	Count int32
}

// StreamHeader is one DecChunk stream record.
type StreamHeader struct {
	Kind     byte
	OldSize  int32
	NewSize  int32
	Resource int32
	Codec    byte
	Option   int32
}

// ReadStreamHeader reads one fixed-size stream record.
func ReadStreamHeader(r io.Reader) (StreamHeader, error) {
	var b [StreamHeaderSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return StreamHeader{}, err
	}
	return StreamHeader{
		Kind:     b[0],
		OldSize:  int32(binary.LittleEndian.Uint32(b[1:5])),
		NewSize:  int32(binary.LittleEndian.Uint32(b[5:9])),
		Resource: int32(binary.LittleEndian.Uint32(b[9:13])),
		Codec:    b[13],
		Option:   int32(binary.LittleEndian.Uint32(b[14:18])),
	}, nil
}

// ReadResources reads a count-prefixed EncInit resource list.
// tooLarge is returned when a count or blob exceeds the decoder limit.
func ReadResources(r io.Reader, tooLarge error) ([]Resource, error) {
	n, err := I32(r)
	if err != nil {
		return nil, err
	}
	if n < 0 || n > 1<<16 {
		return nil, tooLarge
	}
	out := make([]Resource, 0, n)
	for i := int32(0); i < n; i++ {
		name, err := Prefixed(r)
		if err != nil {
			return nil, err
		}
		sz, err := I32(r)
		if err != nil {
			return nil, err
		}
		if sz < 0 || sz > 64<<20 {
			return nil, tooLarge
		}
		data := make([]byte, sz)
		if sz > 0 {
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, err
			}
		}
		out = append(out, Resource{Name: name, Data: data})
	}
	return out, nil
}

// Prefixed reads a u8 length and that many bytes.
func Prefixed(r io.Reader) (string, error) {
	n, err := U8(r)
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

// U8 reads one byte.
func U8(r io.Reader) (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(r, b[:])
	return b[0], err
}

// I32 reads a little-endian int32.
func I32(r io.Reader) (int32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(b[:])), nil
}

// U32 reads a little-endian uint32.
func U32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

// I64 reads a little-endian int64.
func I64(r io.Reader) (int64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b[:])), nil
}

// Bits returns count bits of v starting at index.
func Bits(v int32, index, count uint) int {
	return int((uint32(v) >> index) & ((1 << count) - 1))
}

// ContainsToken reports whether tok appears in s, bounded by start or +,:,.
func ContainsToken(s, tok string) bool {
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

// U32LE reads a little-endian uint32 from the first four bytes.
func U32LE(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// Dedup tracks TDuplicate2 copies inside one XTL0 stream.
type Dedup struct {
	want  map[int32]int32
	store map[int32][]byte
	next  int32
}

// NewDedup indexes dups that still have copies left.
func NewDedup(dups []Dup) *Dedup {
	d := &Dedup{want: make(map[int32]int32, len(dups)), store: make(map[int32][]byte, len(dups))}
	for _, x := range dups {
		if x.Count > 0 {
			d.want[x.Index] = x.Count
		}
	}
	return d
}

// Begin assigns the next stream index. A nil Dedup returns -1.
func (d *Dedup) Begin() int32 {
	if d == nil {
		return -1
	}
	id := d.next
	d.next++
	return id
}

// Save stores data when this index still has copies pending.
func (d *Dedup) Save(id int32, data []byte) {
	if d == nil || id < 0 {
		return
	}
	if d.want[id] > 0 {
		d.store[id] = append([]byte(nil), data...)
	}
}

// CopyDup returns one saved copy. name is the decoder prefix used in errors.
func CopyDup(d *Dedup, name string, src int32) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("%s: %w", name, errDupWithoutTable)
	}
	data, ok := d.store[src]
	if !ok {
		return nil, fmt.Errorf("%s: %w %d", name, errMissingDup, src)
	}
	d.want[src]--
	if d.want[src] <= 0 {
		delete(d.store, src)
		delete(d.want, src)
	}
	return append([]byte(nil), data...), nil
}
