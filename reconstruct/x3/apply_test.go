package x3

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyInstructions(t *testing.T) {
	tests := []struct {
		name string
		old  string
		code []byte
		want string
	}{
		{"literal gaps around source", "abcd", []byte{0x15, 0, 0x13, 2, 1, 2, 0x12, 'X', 'Y', 'Z', 0x16}, "XYbcZ"},
		{"repeated template", "abcdef", []byte{0x15, 0, 0xf, 1, 3, 0xe, 0, 0xd, 1, 0, 0x12, '!', 0x16}, "bcd!bcd"},
		{"fill pattern and zero", "", []byte{0x15, 0, 0x5, 'a', 'b', 5, 0xb, 1, 2, 0x12, '!', 0x16}, "ababa!\x00\x00"},
		{"delta with signed seeks", "abcd", []byte{0x15, 0, 0x14, 0, 4, 0x9, 1, 2, 2, 0x82, 0x11, 1, 255, 0x16}, "badd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyCode(t.Context(), []byte(tt.old), tt.code, len(tt.want))
			require.NoError(t, err)
			require.Equal(t, tt.want, string(got))
			for n := 0; n < len(tt.code); n++ {
				_, err := applyCode(t.Context(), []byte(tt.old), tt.code[:n], len(tt.want))
				require.Error(t, err)
			}
		})
	}
}

func TestApplyRejectsInvalidInstructions(t *testing.T) {
	for _, code := range [][]byte{
		{0x16}, {0x15, 1, 0x16}, {0x15, 0, 0x15, 0}, {0x15, 0, 0xff},
		{0x15, 0, 0x14, 3, 2}, {0x15, 0, 0x14, 0, 5}, {0x15, 0, 0xc, 5},
		{0x15, 0, 0xe, 0}, {0x15, 0, 0x11, 4, 1}, {0x15, 0, 0xc, 4, 0x16, 0},
	} {
		_, err := applyCode(t.Context(), []byte("abcd"), code, 4)
		require.Error(t, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := applyCode(ctx, nil, []byte{0x15, 0, 0x16}, 0)
	require.ErrorIs(t, err, context.Canceled)
}

func TestRecordChecksBothVersions(t *testing.T) {
	old, want := []byte("abcd"), []byte("bcde")
	a, b := checksum(old)
	c, d := checksum(want)
	r := Record{Source: "a", Target: "b", old: fileVersion{size: 4, w1: a, w2: b}, new: fileVersion{size: 4, w1: c, w2: d}, code: []byte{0x15, 0, 0x14, 0, 4, 0x9, 1, 4, 0, 1, 1, 1, 0x16}}
	got, err := r.Apply(t.Context(), old)
	require.NoError(t, err)
	require.Equal(t, want, got)
	_, err = r.Apply(t.Context(), []byte("abce"))
	require.Error(t, err)
	r.new.w2 ^= 1
	_, err = r.Apply(t.Context(), old)
	require.Error(t, err)
}

func TestFilePath(t *testing.T) {
	for _, name := range []string{"../a", "a/../b", "/a", "C:\\a", "a\x00b"} {
		_, err := filePath(name)
		require.Error(t, err)
	}
	got, err := filePath("Data\\file")
	require.NoError(t, err)
	require.Equal(t, "Data/file", got)
}
