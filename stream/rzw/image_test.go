package rzw

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImgDotShift(t *testing.T) {
	// 0x404994: lea 0x200(%rax,%rcx); sar $10.
	require.Zero(t, imgDot([16]int16{}, [8]int16{}, [8]int16{}))
	var feat [16]int16
	feat[0] = 4
	var c0 [8]int16
	c0[0] = 256
	require.Equal(t, (4*256+512)>>10, imgDot(feat, c0, [8]int16{}))
}

func TestImgRiceAdapt(t *testing.T) {
	d := newDec(nil, 16)
	d.img.rice[0] = 2
	// v=9: 9 > 2<<2 (8) → ++
	require.Greater(t, 9, 2<<2)
	d.img.rice[0] = 2
	if 9 > 2<<2 {
		d.img.rice[0] = 3
	}
	require.Equal(t, 3, d.img.rice[0])
	d.img.rice[0] = 3
	if 4 < 1<<3 {
		d.img.rice[0] = 3 - (3+31)>>5
	}
	require.Equal(t, 2, d.img.rice[0])
}

func TestImgExtra20(t *testing.T) {
	// 1.00 0x42b720 / 1.03.7 file 0x29c60 VA 0x42c460.
	want := [20]byte{0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	require.Equal(t, want, imgExtra20)
	require.Equal(t, 5, imgBase20[5])
	require.Equal(t, 7, imgBase20[6])
}
