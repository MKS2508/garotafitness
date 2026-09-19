package xt2png

import (
	"encoding/binary"
	"fmt"
	"io"
)

// XTL0 is XTOOL_PRECOMP in PrecompMain.pas ($304C5458).
const XTL0 = "XTL0"

const (
	kindDefault    = 0
	kindExtended   = 1
	kindNested     = 2
	kindDuplicated = 4
)

const streamHeaderSize = 18

// Header is the XTL0 prefix read by the shipped xtool decode before DecChunk.
type Header struct {
	Depth      int32
	Method     string
	Resources  []Resource
	StoreDD    int32 // unused on FS25 xtool_2020; public 0.7.9 dd#
	Compressed byte  // 1-byte flag after resources; 0 = no inline dups
	Dups       []Dup
	DDMem      int64
}

// Resource is one named blob written by EncInit (gk.key on fg-03).
type Resource struct {
	Name string
	Data []byte
}

// Dup is TDuplicate2: first-seen stream index and extra copy count.
type Dup struct {
	Index int32
	Count int32
}

type streamHeader struct {
	Kind     byte
	OldSize  int32
	NewSize  int32
	Resource int32
	Codec    byte
	Option   int32
}

func parseHeader(r io.Reader) (Header, error) {
	var mag [4]byte
	if _, err := io.ReadFull(r, mag[:]); err != nil {
		return Header{}, fmt.Errorf("xt2png: magic: %w", err)
	}
	if string(mag[:]) != XTL0 {
		return Header{}, errBadMagic
	}
	var h Header
	var err error
	if h.Depth, err = readI32(r); err != nil {
		return Header{}, fmt.Errorf("xt2png: depth: %w", err)
	}
	// Later xtool writes a 16-byte digest after XTL0. Depth is then 0..16.
	if h.Depth < 0 || h.Depth > 16 {
		if _, err := io.CopyN(io.Discard, r, 12); err != nil {
			return Header{}, fmt.Errorf("xt2png: digest: %w", err)
		}
		if h.Depth, err = readI32(r); err != nil {
			return Header{}, fmt.Errorf("xt2png: depth: %w", err)
		}
	}
	if h.Method, err = readPrefixed(r); err != nil {
		return Header{}, fmt.Errorf("xt2png: method: %w", err)
	}
	if h.Resources, err = readResources(r); err != nil {
		return Header{}, fmt.Errorf("xt2png: resources: %w", err)
	}
	// Shipped FS25 xtool.exe (xtool_2020, May 2022) writes a 1-byte flag
	// after EncInit resources, not StoreDD+Compressed from public 0.7.9.
	// Flag 0: dups live in the EncInit .key resources; DecChunk starts at
	// StreamCount. Flag != 0: 16-byte digest + u32 n + n TDuplicate2.
	h.StoreDD = -2
	if h.Compressed, err = readU8(r); err != nil {
		return Header{}, fmt.Errorf("xt2png: flag: %w", err)
	}
	if h.Compressed != 0 {
		if _, err := io.CopyN(io.Discard, r, 16); err != nil {
			return Header{}, fmt.Errorf("xt2png: dd digest: %w", err)
		}
		n, err := readU32(r)
		if err != nil {
			return Header{}, fmt.Errorf("xt2png: ddcount: %w", err)
		}
		if n > 1<<20 {
			return Header{}, errTooLarge
		}
		h.Dups = make([]Dup, n)
		for i := range h.Dups {
			if h.Dups[i].Index, err = readI32(r); err != nil {
				return Header{}, fmt.Errorf("xt2png: dd: %w", err)
			}
			if h.Dups[i].Count, err = readI32(r); err != nil {
				return Header{}, fmt.Errorf("xt2png: dd: %w", err)
			}
		}
	}
	return h, nil
}

func readStreamHeader(r io.Reader) (streamHeader, error) {
	var b [streamHeaderSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return streamHeader{}, err
	}
	return streamHeader{
		Kind:     b[0],
		OldSize:  int32(binary.LittleEndian.Uint32(b[1:5])),
		NewSize:  int32(binary.LittleEndian.Uint32(b[5:9])),
		Resource: int32(binary.LittleEndian.Uint32(b[9:13])),
		Codec:    b[13],
		Option:   int32(binary.LittleEndian.Uint32(b[14:18])),
	}, nil
}

func readResources(r io.Reader) ([]Resource, error) {
	n, err := readI32(r)
	if err != nil {
		return nil, err
	}
	if n < 0 || n > 1<<16 {
		return nil, errTooLarge
	}
	out := make([]Resource, 0, n)
	for i := int32(0); i < n; i++ {
		name, err := readPrefixed(r)
		if err != nil {
			return nil, err
		}
		sz, err := readI32(r)
		if err != nil {
			return nil, err
		}
		if sz < 0 || sz > 64<<20 {
			return nil, errTooLarge
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

func readPrefixed(r io.Reader) (string, error) {
	n, err := readU8(r)
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

func readU8(r io.Reader) (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(r, b[:])
	return b[0], err
}

func readI32(r io.Reader) (int32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(b[:])), nil
}

func readU32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func readI64(r io.Reader) (int64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b[:])), nil
}

func getBits(v int32, index, count uint) int {
	return int((uint32(v) >> index) & ((1 << count) - 1))
}
