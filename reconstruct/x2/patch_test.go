package x2

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApply(t *testing.T) {
	patch := binary.LittleEndian.AppendUint64(nil, 260)
	patch = binary.LittleEndian.AppendUint64(patch, 3)
	patch = append(patch, 0) // 256 bytes
	patch = append(patch, bytes.Repeat([]byte{42}, 256)...)
	patch = binary.LittleEndian.AppendUint64(patch, 4)
	patch = append(patch, 1, 17) // overlapping replacement wins
	old := []byte{1, 2, 3, 4, 5}
	out, err := Apply(old, patch)
	require.NoError(t, err)
	want := append([]byte{1, 2, 3}, bytes.Repeat([]byte{42}, 256)...)
	want[4] = 17
	want = append(want, 0)
	require.Equal(t, want, out)
	require.Equal(t, byte(5), old[4])
	for _, n := range []int{0, 7, 9, 16, 17, len(patch) - 1} {
		_, err := Apply(old, patch[:n])
		require.Error(t, err)
	}
	binary.LittleEndian.PutUint64(patch[8:], 259)
	_, err = Apply(old, patch)
	require.Error(t, err)
	out, err = Apply(old, binary.LittleEndian.AppendUint64(nil, 2))
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2}, out)
}
