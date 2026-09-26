package x5n

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseFS25Head(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("testdata/head.bin")
	require.NoError(t, err)
	info, err := Parse(b)
	require.NoError(t, err)
	require.Len(t, info.OldPaths, 2)
	require.Equal(t, "inner.fgpack", info.OldPaths[1])
	require.Len(t, info.NewPaths, 9)
	require.Equal(t, "shared/", info.NewPaths[1])
	require.Equal(t, uint64(1226032094), info.OldRefSize)
	require.Equal(t, uint64(1633847662), info.NewRefSize)
	require.Len(t, info.OldRefs, 1)
	require.Len(t, info.NewRefs, 7)
	require.Len(t, info.NewRefSizes, 7)
	require.Equal(t, "inner.fgpack", info.OldPaths[info.OldRefs[0]])
}

func TestParseRejectsHDIFF13(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte("HDIFF13&"))
	require.Error(t, err)
}
