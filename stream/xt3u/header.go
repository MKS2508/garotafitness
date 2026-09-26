package xt3u

import (
	"fmt"
	"io"

	"github.com/lucasew/garotafitness/internal/xtl"
)

// XTL0 is XTOOL_PRECOMP in PrecompMain.pas ($304C5458).
const XTL0 = xtl.Magic

const (
	kindDefault    = xtl.KindDefault
	kindExtended   = xtl.KindExtended
	kindNested     = xtl.KindNested
	kindDuplicated = xtl.KindDuplicated
)

// Header is the XTL0 prefix read by xtool decode before DecChunk.
type Header struct {
	Depth      int32
	Method     string
	Resources  []Resource
	StoreDD    int32
	Compressed byte
	Dups       []Dup
	DDMem      int64
}

// Resource is one named blob written by EncInit (gk.key on fg-03).
type Resource = xtl.Resource

// Dup is TDuplicate2: first-seen stream index and extra copy count.
type Dup = xtl.Dup

type streamHeader = xtl.StreamHeader

func parseHeader(r io.Reader) (Header, error) {
	var mag [4]byte
	if _, err := io.ReadFull(r, mag[:]); err != nil {
		return Header{}, fmt.Errorf("xt3u: magic: %w", err)
	}
	if string(mag[:]) != XTL0 {
		return Header{}, errBadMagic
	}
	var h Header
	var err error
	if h.Depth, err = xtl.I32(r); err != nil {
		return Header{}, fmt.Errorf("xt3u: depth: %w", err)
	}
	if h.Method, err = xtl.Prefixed(r); err != nil {
		return Header{}, fmt.Errorf("xt3u: method: %w", err)
	}
	if h.Resources, err = xtl.ReadResources(r, errTooLarge); err != nil {
		return Header{}, fmt.Errorf("xt3u: resources: %w", err)
	}
	if h.StoreDD, err = xtl.I32(r); err != nil {
		return Header{}, fmt.Errorf("xt3u: storedd: %w", err)
	}
	if h.Compressed, err = xtl.U8(r); err != nil {
		return Header{}, fmt.Errorf("xt3u: compressed: %w", err)
	}
	if h.StoreDD > -2 {
		n, err := xtl.U32(r)
		if err != nil {
			return Header{}, fmt.Errorf("xt3u: ddcount: %w", err)
		}
		if n > 1<<20 {
			return Header{}, errTooLarge
		}
		h.Dups = make([]Dup, n)
		for i := range h.Dups {
			if h.Dups[i].Index, err = xtl.I32(r); err != nil {
				return Header{}, fmt.Errorf("xt3u: dd: %w", err)
			}
			if h.Dups[i].Count, err = xtl.I32(r); err != nil {
				return Header{}, fmt.Errorf("xt3u: dd: %w", err)
			}
		}
		if h.DDMem, err = xtl.I64(r); err != nil {
			return Header{}, fmt.Errorf("xt3u: ddmem: %w", err)
		}
	}
	return h, nil
}
