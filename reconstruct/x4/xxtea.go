package x4

import "encoding/binary"

const xxteaDelta = 0x9e3779b9

// XXTEAEncrypt is a leftover placeholder cipher used by brute tests.
func XXTEAEncrypt(v []byte, key [4]uint32) {
	xxteaEncrypt(v, key)
}

// Pad8 matches x4.exe: round up to 8 and store the pad length in the last byte.
func Pad8(in []byte) []byte {
	return pad8(in)
}

func xxteaEncrypt(v []byte, key [4]uint32) {
	n := len(v) / 4
	if n < 2 {
		return
	}
	w := make([]uint32, n)
	for i := range n {
		w[i] = binary.LittleEndian.Uint32(v[i*4:])
	}
	rounds := 6 + 52/n
	sum := uint32(0)
	z := w[n-1]
	for range rounds {
		sum += xxteaDelta
		e := (sum >> 2) & 3
		for p := range n - 1 {
			y := w[p+1]
			w[p] += ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (key[(uint32(p)&3)^e] ^ z))
			z = w[p]
		}
		y := w[0]
		w[n-1] += ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (key[(uint32(n-1)&3)^e] ^ z))
		z = w[n-1]
	}
	for i, x := range w {
		binary.LittleEndian.PutUint32(v[i*4:], x)
	}
}

func pad8(in []byte) []byte {
	n := len(in)
	p := (n + 7) &^ 7
	out := make([]byte, p)
	copy(out, in)
	if p > n {
		out[p-1] = byte(p - n)
	}
	return out
}
