// Package i3d reproduces the Giants shapes cipher shipped as FitGirl's
// two-argument fgpack.exe (ConsoleApp1 wrapping I3DShapesTool.Lib).
package i3d

import (
	_ "embed"
	"encoding/binary"
	"fmt"
)

//go:embed keyconst.bin
var keyConstRaw []byte

const cryptBlock = 64

var keyConst [4096]uint32

func init() {
	if len(keyConstRaw) != 4*len(keyConst) {
		panic("i3d: keyconst.bin size")
	}
	for i := range keyConst {
		keyConst[i] = binary.LittleEndian.Uint32(keyConstRaw[i*4:])
	}
}

type decryptor struct {
	key [16]uint32
}

func newDecryptor(seed byte) *decryptor {
	d := &decryptor{}
	off := int(seed) << 4
	for i := range d.key {
		d.key[i] = keyConst[off+i]
	}
	d.key[8] = 0
	d.key[9] = 0
	return d
}

func (d *decryptor) decrypt(buf []byte, blockIndex uint64) {
	if len(buf) == 0 {
		return
	}
	n := roundUp(len(buf), cryptBlock)
	padded := make([]byte, n)
	copy(padded, buf)
	words := make([]uint32, n/4)
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(padded[i*4:])
	}
	d.decryptBlocks(words, blockIndex)
	for i, w := range words {
		binary.LittleEndian.PutUint32(padded[i*4:], w)
	}
	copy(buf, padded)
}

func (d *decryptor) decryptBlocks(buf []uint32, blockIndex uint64) {
	key := d.key
	key[8] = uint32(blockIndex)
	key[9] = uint32(blockIndex >> 32)
	tmp := make([]uint32, 16)
	ctr := blockIndex
	for i := 0; i < len(buf); i += 16 {
		copy(tmp, key[:])
		for range 10 {
			shuffle1(tmp, 0x0, 0xC, 0x4, 0x8)
			shuffle1(tmp, 0x5, 0x1, 0x9, 0xD)
			shuffle1(tmp, 0xA, 0x6, 0xE, 0x2)
			shuffle1(tmp, 0xF, 0xB, 0x3, 0x7)
			shuffle2(tmp, 0x3, 0x0, 0x1, 0x2)
			shuffle2(tmp, 0x4, 0x5, 0x6, 0x7)
			shuffle1(tmp, 0xA, 0x9, 0xB, 0x8)
			shuffle2(tmp, 0xE, 0xF, 0xC, 0xD)
		}
		for j := range 16 {
			buf[i+j] ^= key[j] + tmp[j]
		}
		ctr++
		key[8] = uint32(ctr)
		key[9] = uint32(ctr >> 32)
	}
}

func shuffle1(key []uint32, i1, i2, i3, i4 int) {
	key[i3] ^= rol(key[i2]+key[i1], 7)
	key[i4] ^= rol(key[i3]+key[i1], 9)
	key[i2] ^= rol(key[i3]+key[i4], 13)
	key[i1] ^= ror(key[i2]+key[i4], 14)
}

func shuffle2(key []uint32, i1, i2, i3, i4 int) {
	key[i3] ^= rol(key[i2]+key[i1], 7)
	key[i4] ^= rol(key[i2]+key[i3], 9)
	key[i1] ^= rol(key[i3]+key[i4], 13)
	key[i2] ^= ror(key[i4]+key[i1], 14)
}

func rol(v uint32, bits int) uint32 { return v<<bits | v>>(32-bits) }
func ror(v uint32, bits int) uint32 { return v>>bits | v<<(32-bits) }

func roundUp(n, to int) int {
	if n%to == 0 {
		return n
	}
	return n + (to - n%to)
}

func apply(in []byte) ([]byte, error) {
	if len(in) < 1 {
		return nil, fmt.Errorf("i3d: empty input")
	}
	d := newDecryptor(in[0])
	out := make([]byte, 0, len(in))
	out = append(out, in[0])
	rest := in[1:]
	for len(rest) > 0 {
		if len(rest) < 8 {
			return nil, fmt.Errorf("i3d: truncated record")
		}
		idx := binary.LittleEndian.Uint32(rest[:4])
		size := binary.LittleEndian.Uint32(rest[4:8])
		rest = rest[8:]
		if uint64(len(rest)) < uint64(size) {
			return nil, fmt.Errorf("i3d: truncated payload")
		}
		payload := append([]byte(nil), rest[:size]...)
		rest = rest[size:]
		d.decrypt(payload, uint64(idx))
		var hdr [8]byte
		binary.LittleEndian.PutUint32(hdr[:4], idx)
		binary.LittleEndian.PutUint32(hdr[4:], size)
		out = append(out, hdr[:]...)
		out = append(out, payload...)
	}
	return out, nil
}
