package magic2

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMetadata(t *testing.T) {
	data, err := hex.DecodeString("fa037205321aa80fe55eec9cd749c75c001b67eeacea3e58e13e741a9cbc8c0cac706f5e11")
	require.NoError(t, err)
	want := []segment{{0, 282884, 73493, 0}, {14, 13564, 1783, 0}, {0, 36608, 5371, 0}, {12, 13575, 2145, 0}, {14, 13561, 1435, 0}, {0, 70697, 8829, 0}, {63, 0, 0, 0}}
	m := newMetadata(data)
	for _, w := range want {
		got, err := m.next()
		require.NoError(t, err)
		require.Equal(t, w, got)
	}
	require.NoError(t, m.r.finish())
	for n := 0; n < len(data); n++ {
		m := newMetadata(data[:n])
		for range want {
			if _, err := m.next(); err != nil {
				break
			}
		}
		require.Error(t, m.r.finish())
	}
}
