package magic2

import (
	"bytes"
	"io"
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lucasew/garotafitness/internal/fixtest"
	"github.com/stretchr/testify/require"
)

func TestHeader(t *testing.T) {
	for _, tt := range []struct {
		name       string
		dictionary uint32
	}{{"fg06.head", 16 << 20}, {"fg02.head", 480 << 20}} {
		t.Run(tt.name, func(t *testing.T) {
			b, err := lewpath.New(tt.name).ReadFile(fixtest.Root(t))
			require.NoError(t, err)
			r := bytes.NewReader(b)
			h, err := ParseHeader(r)
			require.NoError(t, err)
			require.Equal(t, tt.dictionary, h.DictionarySize)
			require.True(t, h.Mixed)
			require.Equal(t, 1, h.Workers)
			require.False(t, h.Independent)
			require.False(t, h.ROLZ)
			require.False(t, h.LongDistance)
			require.Equal(t, uint(4), h.ClassShift)
			require.Equal(t, uint(4), h.PredictionShift)
			require.Zero(t, h.HighShift)
			require.Zero(t, h.LowShift)
			require.Equal(t, uint(4), h.WeightShift)
			rest, _ := io.ReadAll(r)
			require.Equal(t, b[9:], rest)
		})
	}
}
func TestHeaderTruncated(t *testing.T) {
	for n := 0; n < 9; n++ {
		_, err := ParseHeader(bytes.NewReader(make([]byte, n)))
		require.Error(t, err)
	}
}
