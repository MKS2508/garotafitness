package x4

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackPadsTo8(t *testing.T) {
	t.Parallel()
	out, err := Pack([]File{{Name: "n/a.txt", Data: []byte("hi")}}, "02", "01")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(out), 8)
	require.Zero(t, len(out)%8)
}
func TestPackRejectsVersion(t *testing.T) {
	t.Parallel()
	_, err := Pack(nil, "01", "01")
	require.Error(t, err)
}
