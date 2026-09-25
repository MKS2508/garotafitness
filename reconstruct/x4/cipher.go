package x4

import "encoding/binary"

// DES PC-1 (64→56), PC-2 (56→48), and per-round left rotations.
var desPC1 = [56]byte{
	57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
	59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
	61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
}
var desPC2 = [48]byte{
	14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
}
var desRot = [16]byte{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

type farmCipher struct {
	subkeys [32]uint32
	sbox    [256]byte
}

func newFarmCipher(key [4]uint32) farmCipher {
	var c farmCipher
	// RC4 KSA key is k2||k3||k0||k1 in little-endian bytes (DLL edi+0x190).
	var sched [16]byte
	binary.LittleEndian.PutUint32(sched[0:], key[2])
	binary.LittleEndian.PutUint32(sched[4:], key[3])
	binary.LittleEndian.PutUint32(sched[8:], key[0])
	binary.LittleEndian.PutUint32(sched[12:], key[1])
	for i := range 256 {
		c.sbox[i] = byte(i)
	}
	var j byte
	for i := range 256 {
		j += c.sbox[i] + sched[i&15]
		c.sbox[i], c.sbox[j] = c.sbox[j], c.sbox[i]
	}

	// DES key schedule from k0||k1.
	var key64 [8]byte
	binary.LittleEndian.PutUint32(key64[0:], key[0])
	binary.LittleEndian.PutUint32(key64[4:], key[1])
	bit := func(n byte) uint64 {
		bi := (n - 1) / 8
		bj := 7 - ((n - 1) % 8)
		return uint64((key64[bi] >> bj) & 1)
	}
	var cd uint64
	for _, pos := range desPC1 {
		cd = (cd << 1) | bit(pos)
	}
	c28 := uint32(cd>>28) & 0x0fffffff
	d28 := uint32(cd) & 0x0fffffff
	for round := range 16 {
		rot := uint32(desRot[round])
		c28 = ((c28 << rot) | (c28 >> (28 - rot))) & 0x0fffffff
		d28 = ((d28 << rot) | (d28 >> (28 - rot))) & 0x0fffffff
		combined := (uint64(c28) << 28) | uint64(d28)
		cdBit := func(pos byte) byte {
			return byte((combined >> (56 - pos)) & 1)
		}
		var six [8]byte
		for i, p := range desPC2 {
			six[i/6] = (six[i/6] << 1) | cdBit(p)
		}
		c.subkeys[round*2] = uint32(six[0])<<24 | uint32(six[1])<<16 | uint32(six[2])<<8 | uint32(six[3])
		c.subkeys[round*2+1] = uint32(six[4])<<24 | uint32(six[5])<<16 | uint32(six[6])<<8 | uint32(six[7])
	}
	return c
}

func initialPerm(block []byte) (even, odd uint32) {
	b := func(i int) int { return int(block[i]) }
	even = sbox7[b(7)&0x55]
	even = (even << 1) | sbox7[b(6)&0x55]
	even = (even << 1) | sbox7[b(5)&0x55]
	even = (even << 1) | sbox7[b(4)&0x55]
	even = (even << 1) | sbox7[b(3)&0x55]
	even = (even << 1) | sbox7[b(2)&0x55]
	even = (even << 1) | sbox7[b(1)&0x55]
	even = (even << 1) | sbox7[b(0)&0x55]
	odd = sbox7[(b(7)>>1)&0x55]
	odd = (odd << 1) | sbox7[(b(6)>>1)&0x55]
	odd = (odd << 1) | sbox7[(b(5)>>1)&0x55]
	odd = (odd << 1) | sbox7[(b(4)>>1)&0x55]
	odd = (odd << 1) | sbox7[(b(3)>>1)&0x55]
	odd = (odd << 1) | sbox7[(b(2)>>1)&0x55]
	odd = (odd << 1) | sbox7[(b(1)>>1)&0x55]
	odd = (odd << 1) | sbox7[(b(0)>>1)&0x55]
	return even, odd
}

func finalPerm(l, r uint32) [8]byte {
	var ecx, eax uint32
	for _, shift := range []int{24, 16, 8, 0} {
		ecx = ecx << 1
		ecx |= sbox8[(l>>shift)&0xf]
		ecx = ecx << 1
		ecx |= sbox8[(r>>shift)&0xf]
	}
	for _, shift := range []int{28, 20, 12, 4} {
		eax = eax << 1
		eax |= sbox8[(l>>shift)&0xf]
		eax = eax << 1
		eax |= sbox8[(r>>shift)&0xf]
	}
	return [8]byte{
		byte(ecx >> 24), byte(ecx >> 16), byte(ecx >> 8), byte(ecx),
		byte(eax >> 24), byte(eax >> 16), byte(eax >> 8), byte(eax),
	}
}

func (c *farmCipher) feistelRound(r, ka, kb uint32) uint32 {
	rrot := r>>15 | r<<17
	idx9 := (((ka >> 12) ^ rrot) >> 12) & 0x3f
	idx10 := (((ka >> 8) ^ rrot) >> 8) & 0x3f
	idx11 := (((ka >> 4) ^ rrot) >> 4) & 0x3f
	idx12 := (ka ^ rrot) & 0x3f
	spa := sbox9[idx9] | sbox10[idx10] | sbox11[idx11] | sbox12[idx12]
	idx13 := (((kb >> 13) ^ r) >> 11) & 0x3f
	idx14 := (((kb >> 9) ^ r) >> 7) & 0x3f
	idx15 := (((kb >> 5) ^ r) >> 3) & 0x3f
	idx16 := ((rrot >> 16) ^ kb) & 0x3f
	spb := sbox13[idx13] | sbox14[idx14] | sbox15[idx15] | sbox16[idx16]
	return spa | spb
}

func (c *farmCipher) feistel(a, b uint32, rounds int, forward bool) (uint32, uint32) {
	for i := range rounds {
		var keyIdx int
		if forward {
			keyIdx = 2 * i
		} else {
			keyIdx = 2*(rounds-1) - 2*i
		}
		f := c.feistelRound(b, c.subkeys[keyIdx], c.subkeys[keyIdx+1])
		a, b = b, a^f
	}
	return a, b
}

// rc4Keystream is the DLL's 8-byte RC4 variant: i=1..4, then j resets to s[1] and i restarts.
func rc4Keystream(state *[256]byte) (out [8]byte) {
	var j byte
	for i := byte(1); i <= 4; i++ {
		j += state[i]
		state[i], state[j] = state[j], state[i]
		out[i-1] = state[state[i]+state[j]]
	}
	j = state[1]
	for i := byte(1); i <= 4; i++ {
		if i > 1 {
			j += state[i]
		}
		state[i], state[j] = state[j], state[i]
		out[i+3] = state[state[i]+state[j]]
	}
	return out
}

func rc4Halves(state *[256]byte) (d1, d2 uint32) {
	ks := rc4Keystream(state)
	d1 = binary.LittleEndian.Uint32(ks[0:4])
	d2 = binary.LittleEndian.Uint32(ks[4:8])
	return d1, d2
}

func blockParams(pos int) (rounds int, useRC4 bool) {
	cycle := pos % 34
	switch {
	case cycle <= 31:
		blockNum := cycle + 1
		return (blockNum + 1) / 2, blockNum%2 == 0
	case cycle == 32:
		return 0, false
	default:
		return 0, true
	}
}

func (c *farmCipher) encrypt(buf []byte) {
	n := len(buf) / 8
	if n == 0 {
		return
	}
	sbox := c.sbox
	for pos := range n {
		off := pos * 8
		rounds, useRC4 := blockParams(pos)
		a, b := initialPerm(buf[off : off+8])
		if useRC4 {
			d1, d2 := rc4Halves(&sbox)
			a ^= d1
			b ^= d2
		}
		a, b = c.feistel(a, b, rounds, true)
		out := finalPerm(a, b)
		copy(buf[off:], out[:])
	}
}

func (c *farmCipher) decrypt(buf []byte) {
	n := len(buf) / 8
	if n == 0 {
		return
	}
	sbox := c.sbox
	for pos := range n {
		off := pos * 8
		rounds, useRC4 := blockParams(pos)
		a, b := initialPerm(buf[off : off+8])
		a, b = c.feistel(a, b, rounds, false)
		if useRC4 {
			d1, d2 := rc4Halves(&sbox)
			a ^= d2
			b ^= d1
		}
		out := finalPerm(a, b)
		copy(buf[off:], out[:])
	}
}
