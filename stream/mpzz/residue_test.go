package mpzz

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBookCacheUnusedEntries(t *testing.T) {
	for _, tt := range []struct {
		name string
		used int
		want int
	}{
		{"compact", 1, 0},
		{"quarter occupancy", 2, 1},
		{"dense", 7, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := bookCache{capacity: 2}
			b := codebook{lengths: make([]byte, 8), quant: []int{0, 1}}
			copy(b.lengths, bytes.Repeat([]byte{3}, tt.used))
			require.Equal(t, 0, c.selectBook(&b, nil))
			b.lengths = bytes.Repeat([]byte{3}, 8)
			require.Equal(t, tt.want, c.selectBook(&b, nil))
		})
	}
}
