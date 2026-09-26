package xt2png

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
type Resource = xtl.Resource

// Dup is TDuplicate2: first-seen stream index and extra copy count.
type Dup = xtl.Dup

type streamHeader = xtl.StreamHeader

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
	if h.Depth, err = xtl.I32(r); err != nil {
		return Header{}, fmt.Errorf("xt2png: depth: %w", err)
	}
	// Later xtool writes a 16-byte digest after XTL0. Depth is then 0..16.
	if h.Depth < 0 || h.Depth > 16 {
		if _, err := io.CopyN(io.Discard, r, 12); err != nil {
			return Header{}, fmt.Errorf("xt2png: digest: %w", err)
		}
		if h.Depth, err = xtl.I32(r); err != nil {
			return Header{}, fmt.Errorf("xt2png: depth: %w", err)
		}
	}
	if h.Method, err = xtl.Prefixed(r); err != nil {
		return Header{}, fmt.Errorf("xt2png: method: %w", err)
	}
	if h.Resources, err = xtl.ReadResources(r, errTooLarge); err != nil {
		return Header{}, fmt.Errorf("xt2png: resources: %w", err)
	}
	// Shipped FS25 xtool.exe (xtool_2020, May 2022) writes a 1-byte flag
	// after EncInit resources, not StoreDD+Compressed from public 0.7.9.
	// Flag 0: dups live in the EncInit .key resources; DecChunk starts at
	// StreamCount. Flag != 0: 16-byte digest + u32 n + n TDuplicate2.
	h.StoreDD = -2
	if h.Compressed, err = xtl.U8(r); err != nil {
		return Header{}, fmt.Errorf("xt2png: flag: %w", err)
	}
	if h.Compressed != 0 {
		if _, err := io.CopyN(io.Discard, r, 16); err != nil {
			return Header{}, fmt.Errorf("xt2png: dd digest: %w", err)
		}
		n, err := xtl.U32(r)
		if err != nil {
			return Header{}, fmt.Errorf("xt2png: ddcount: %w", err)
		}
		if n > 1<<20 {
			return Header{}, errTooLarge
		}
		h.Dups = make([]Dup, n)
		for i := range h.Dups {
			if h.Dups[i].Index, err = xtl.I32(r); err != nil {
				return Header{}, fmt.Errorf("xt2png: dd: %w", err)
			}
			if h.Dups[i].Count, err = xtl.I32(r); err != nil {
				return Header{}, fmt.Errorf("xt2png: dd: %w", err)
			}
		}
	}
	return h, nil
}
