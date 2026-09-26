package garotafitness

import (
	"context"
	"crypto/md5"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToolsetMatchByNameAndHash(t *testing.T) {
	t.Parallel()
	c, err := reconstructToolset.match("fgpack.exe", "")
	require.NoError(t, err)
	require.Equal(t, "lzma", c.id)
	c, err = reconstructToolset.match("fgpack.exe", "a95222984f60e3f5bea4099cab85868946523391b0e50d7f6dcc5e866d0b0dbd")
	require.NoError(t, err)
	require.Equal(t, "lzma", c.id)
	c, err = reconstructToolset.match("fgpack.exe", "eb9a914ff781bc2f088e70d1b99faca73d98a96325a4a154cf52b3b52a4f860a")
	require.NoError(t, err)
	require.Equal(t, "i3d", c.id)
	_, err = reconstructToolset.match("fgpack.exe", "deadbeef")
	require.ErrorIs(t, err, errUnknownToolHash)
	c, err = reconstructToolset.match("x4.exe", "7889aadec74fe2e4940a3dab081b8d560d7d751b0ed13cfc90b8986ca6ae084f")
	require.NoError(t, err)
	require.Equal(t, "defarm", c.id)
	_, err = reconstructToolset.match("x4.exe", "deadbeef")
	require.ErrorIs(t, err, errUnknownToolHash)
}

func TestToolsetMatchByHash(t *testing.T) {
	t.Parallel()
	s := &toolset{byHash: map[string]codec{}, byName: map[string][]codec{}}
	s.add(codec{id: "lzma", sha256: "aaa", names: []string{"codec-test.exe"}})
	s.add(codec{id: "other", sha256: "bbb", names: []string{"codec-test.exe"}})
	c, err := s.match("codec-test.exe", "BBB")
	require.NoError(t, err)
	require.Equal(t, "other", c.id)
	_, err = s.match("codec-test.exe", "")
	require.Error(t, err, "expected missing hash")
	_, err = s.match("codec-test.exe", "ccc")
	require.ErrorIs(t, err, errUnknownToolHash)
}

func TestToolsetSameHashDifferentName(t *testing.T) {
	t.Parallel()
	const xdelta = "09763ca90c09a5f815a94527399b1f2a88685e9de462e2ff1bc5648d320e707a"
	c, err := reconstructToolset.match("xdelta3.exe", xdelta)
	require.NoError(t, err)
	require.Equal(t, "xdelta", c.id)
	require.Equal(t, "x.exe", reconstructToolset.canonical("packer.exe", xdelta))
}

func TestToolsetRunByChecksum(t *testing.T) {
	t.Parallel()
	s := &toolset{byHash: map[string]codec{}, byName: map[string][]codec{}}
	s.add(codec{id: "bad", sha256: "aaa", names: []string{"codec-test.exe"}, encode: func(context.Context, []byte, []string) ([]byte, error) {
		return []byte("no"), nil
	}})
	s.add(codec{id: "good", sha256: "bbb", names: []string{"codec-test.exe"}, encode: func(context.Context, []byte, []string) ([]byte, error) {
		return []byte("ok"), nil
	}})
	want := md5sum([]byte("ok"))
	out, err := s.run(t.Context(), "codec-test.exe", "ccc", nil, nil, want)
	require.NoError(t, err)
	require.Equal(t, "ok", string(out))
	_, err = s.run(t.Context(), "codec-test.exe", "ccc", nil, nil, nil)
	require.ErrorIs(t, err, errUnknownToolHash)
}

func TestToolsetRunI3D(t *testing.T) {
	t.Parallel()
	in := []byte{0x2a, 0, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4}
	const fs25 = "eb9a914ff781bc2f088e70d1b99faca73d98a96325a4a154cf52b3b52a4f860a"
	out, err := reconstructToolset.run(t.Context(), "fgpack.exe", fs25, in, []string{"a.shapes", "a.fgr_"}, nil)
	require.NoError(t, err)
	require.NotEqual(t, in, out, "i3d did not change payload")
	back, err := reconstructToolset.run(t.Context(), "fgpack.exe", fs25, out, []string{"a.fgr_", "a.shapes"}, nil)
	require.NoError(t, err)
	require.Equal(t, in, back)
}

func md5sum(b []byte) []byte {
	h := md5.Sum(b)
	return h[:]
}
