package magic2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExplicitAlphaContext(t *testing.T) {
	// VA 0x14002bde0: CDF at 0x285c00 + left*8704 + above*544 + diag*34.
	require.Equal(t, 3*8704+1*544+2*34, explicitAlphaContext(3, 1, 2))
	require.Zero(t, explicitAlphaContext(0, 0, 0))
}

func TestExplicitAlphaNeighbors(t *testing.T) {
	var left, top [8]byte
	putNibble(&left, 3, 1)
	putNibble(&left, 7, 2)
	putNibble(&left, 11, 3)
	putNibble(&left, 15, 4)
	putNibble(&top, 12, 5)
	putNibble(&top, 13, 6)
	putNibble(&top, 14, 7)
	putNibble(&top, 15, 8)
	l0 := uint32(left[0]) | uint32(left[1])<<8 | uint32(left[2])<<16 | uint32(left[3])<<24
	l1 := uint32(left[4]) | uint32(left[5])<<8 | uint32(left[6])<<16 | uint32(left[7])<<24
	leftEdge := [4]int{int(l0>>12) & 15, int(l0>>28) & 15, int(l1>>12) & 15, int(l1>>28) & 15}
	require.Equal(t, [4]int{1, 2, 3, 4}, leftEdge)
	tb := uint32(top[4]) | uint32(top[5])<<8 | uint32(top[6])<<16 | uint32(top[7])<<24
	topRow := [4]int{int(tb>>16) & 15, int(tb>>20) & 15, int(tb>>24) & 15, int(tb>>28) & 15}
	require.Equal(t, [4]int{5, 6, 7, 8}, topRow)
	require.Equal(t, 1*8704+5*544+1*34, explicitAlphaContext(leftEdge[0], topRow[0], leftEdge[0]))
}

func putNibble(b *[8]byte, pixel, v int) {
	bit := pixel * 4
	u := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	u &^= 15 << uint(bit)
	u |= uint64(v&15) << uint(bit)
	for i := range b {
		b[i] = byte(u >> uint(i*8))
	}
}
