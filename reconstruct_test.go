package garotafitness

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/lewtec/lewkit/x/test"
	"github.com/lucasew/garotafitness/internal/scratch"
	"github.com/stretchr/testify/require"
)

func TestInstalledChecksums(t *testing.T) {
	s := &reconstruction{files: map[string][]byte{"Data/a.txt": []byte("abc")}}
	manifest := "900150983cd24fb0d6963f7d28e17f72 *..\\Data\\a.txt\r\n"
	require.NoError(t, s.verifyInstalled(t.Context(), manifest, "_Redist"))
	for _, bad := range []string{
		"", "not a checksum\n", strings.Replace(manifest, "9001", "0001", 1),
		strings.Replace(manifest, "a.txt", "missing", 1),
		strings.Replace(manifest, "Data\\a.txt", "..\\escape", 1),
		strings.Replace(manifest, "Data\\a.txt", "C:\\escape", 1),
	} {
		require.Error(t, s.verifyInstalled(t.Context(), bad, "_Redist"), "accepted %q", bad)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, s.verifyInstalled(ctx, manifest, "_Redist"), context.Canceled)
}

func TestStagingRejectsEscapes(t *testing.T) {
	s := &reconstruction{files: map[string][]byte{}}
	for _, name := range []string{"../escape", "/escape"} {
		_, err := s.Create(name)
		require.Error(t, err, "accepted %q", name)
	}
	require.Empty(t, s.files, "wrote an invalid member")
}

func TestDiskStagingRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := scratch.WithDir(t.Context(), t.TempDir())
	s, err := newDiskStaging(ctx)
	require.NoError(t, err)
	test.CloseOnCleanup(t, s)
	w, err := s.Create("a/b.txt")
	require.NoError(t, err)
	_, err = io.WriteString(w, "hello")
	require.NoError(t, err)
	require.NoError(t, w.Close())
	got, err := s.require("a/b.txt")
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
	dst, err := newDiskStaging(ctx)
	require.NoError(t, err)
	test.CloseOnCleanup(t, dst)
	n, err := dst.ingest(ctx, s, "a/b.txt", "c/d.txt")
	require.NoError(t, err)
	require.Equal(t, int64(5), n)
	got, err = dst.require("c/d.txt")
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
	require.NoError(t, s.putFile("e.txt", []byte("x")))
	r, size, err := s.openRead("e.txt")
	require.NoError(t, err)
	test.CloseOnCleanup(t, r)
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, int64(1), size)
	require.Equal(t, []byte("x"), b)
}

func TestDestStageDirIsTmp(t *testing.T) {
	t.Parallel()
	d, err := OpenDirDest(t.TempDir())
	require.NoError(t, err)
	test.CloseOnCleanup(t, d)
	dir, err := destStageDir(d)
	require.NoError(t, err)
	ctx := scratch.WithDir(t.Context(), dir)
	s, err := scratch.MkdirTemp(ctx, "garotafitness-stage-*")
	require.NoError(t, err)
	test.CloseOnCleanup(t, s)
	require.Equal(t, "tmp", s.Rel().Parent().String())
	ok, err := s.Rel().IsDir(d)
	require.NoError(t, err)
	require.True(t, ok, "%s missing", s.Rel())
}

func TestStagingCtxRebindsWithDir(t *testing.T) {
	t.Parallel()
	d, err := OpenDirDest(t.TempDir())
	require.NoError(t, err)
	test.CloseOnCleanup(t, d)
	dir, err := destStageDir(d)
	require.NoError(t, err)
	p := &reconstructionPlan{scratchDir: dir}
	s, err := newDiskStaging(p.stagingCtx(t.Context()))
	require.NoError(t, err)
	test.CloseOnCleanup(t, s)
	require.Equal(t, "tmp", s.stage.Rel().Parent().String())
}
