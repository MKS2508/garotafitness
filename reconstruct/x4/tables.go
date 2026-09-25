package x4

// Giants defarm is DES with a custom P-box and a 34-block schedule.
// S-boxes are FIPS 46-3; fused S+P and IP/FP spread tables match the
// inner DLL (same derivation as Paint-a-Farm/gar-lib).

func linearizeSbox(sbox [4][16]byte) [64]byte {
	var out [64]byte
	for i := range 64 {
		row := ((i >> 5) << 1) | (i & 1)
		col := (i >> 1) & 0xf
		out[i] = sbox[row][col]
	}
	return out
}

var desSboxes = [8][64]byte{
	linearizeSbox([4][16]byte{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	}),
	linearizeSbox([4][16]byte{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	}),
	linearizeSbox([4][16]byte{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	}),
	linearizeSbox([4][16]byte{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	}),
	linearizeSbox([4][16]byte{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	}),
	linearizeSbox([4][16]byte{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	}),
	linearizeSbox([4][16]byte{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	}),
	linearizeSbox([4][16]byte{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	}),
}

// Custom P-box (0-indexed). Four bits per S-box slot, MSB first.
// Slot order is S2,S1,S3,S4,S5,S6,S8,S7.
var customPbox = [32]byte{
	23, 15, 9, 1,
	19, 4, 5, 14,
	8, 16, 2, 20,
	6, 12, 22, 31,
	24, 18, 7, 29,
	28, 3, 21, 13,
	0, 26, 10, 25,
	27, 30, 17, 11,
}

var sboxOrder = [8]int{1, 0, 2, 3, 4, 5, 7, 6}

func buildFusedSP(slot int) [64]uint32 {
	sbox := desSboxes[sboxOrder[slot]]
	base := slot * 4
	var table [64]uint32
	for i := range 64 {
		val := uint32(sbox[i])
		var out uint32
		for b := range 4 {
			if val&(1<<(3-b)) != 0 {
				out |= 1 << customPbox[base+b]
			}
		}
		table[i] = out
	}
	return table
}

func buildSbox7() [86]uint32 {
	var table [86]uint32
	for i := range 86 {
		var val uint32
		if i&1 != 0 {
			val |= 1
		}
		if i&4 != 0 {
			val |= 1 << 8
		}
		if i&16 != 0 {
			val |= 1 << 16
		}
		if i&64 != 0 {
			val |= 1 << 24
		}
		table[i] = val
	}
	return table
}

func buildSbox8() [16]uint32 {
	var table [16]uint32
	for i := range uint32(16) {
		var val uint32
		if i&1 != 0 {
			val |= 1 << 24
		}
		if i&2 != 0 {
			val |= 1 << 16
		}
		if i&4 != 0 {
			val |= 1 << 8
		}
		if i&8 != 0 {
			val |= 1
		}
		table[i] = val
	}
	return table
}

var (
	sbox7  = buildSbox7()
	sbox8  = buildSbox8()
	sbox9  = buildFusedSP(0)
	sbox10 = buildFusedSP(1)
	sbox11 = buildFusedSP(2)
	sbox12 = buildFusedSP(3)
	sbox13 = buildFusedSP(4)
	sbox14 = buildFusedSP(5)
	sbox15 = buildFusedSP(6)
	sbox16 = buildFusedSP(7)
)
