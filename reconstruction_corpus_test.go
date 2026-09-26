package garotafitness

import (
	"crypto/md5"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/test"
	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
)

// Filter the directory view instead of creating symlinks outside an open root.
type requiredCorpus struct{ fs.FS }

func (s requiredCorpus) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(s.FS, name)
	var out []fs.DirEntry
	for _, entry := range entries {
		if !strings.Contains(entry.Name(), "optional") {
			out = append(out, entry)
		}
	}
	return out, err
}

func (s requiredCorpus) Open(name string) (fs.File, error) {
	if strings.Contains(name, "optional") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return s.FS.Open(name)
}

// This checks the public extraction flow and then reopens every installed file.
// It is opt-in because reconstructing the full corpus takes several minutes.
func TestExtractInstalledRimWorld(t *testing.T) {
	mode := os.Getenv("GAROTAFITNESS_FULL_EXTRACT")
	if mode == "" {
		t.Skip("set GAROTAFITNESS_FULL_EXTRACT=all or required for full corpus extraction")
	}
	require.True(t, mode == "all" || mode == "required", "GAROTAFITNESS_FULL_EXTRACT must be all or required")
	var source fs.FS = corpus.Open(t)
	if ok, err := lewpath.New("setup.exe").Exists(source); err != nil || !ok {
		t.Skip("corpus not mounted")
	}
	if mode == "required" {
		source = requiredCorpus{source}
	}
	dst, err := OpenDirDest(t.TempDir())
	require.NoError(t, err)
	test.CloseOnCleanup(t, dst)
	require.NoError(t, (Extractor{Source: source, Dest: dst}).Extract(t.Context()))
	manifest, err := lewpath.New("_Redist/fitgirl.md5").ReadFile(dst)
	require.NoError(t, err)
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		want, name, ok := strings.Cut(strings.TrimSuffix(line, "\r"), " *..\\")
		require.True(t, ok, "invalid manifest line %q", line)
		f, err := lewpath.New(strings.ReplaceAll(name, "\\", "/")).Open(dst)
		require.NoError(t, err)
		h := md5.New()
		_, err = io.Copy(h, f)
		require.NoError(t, f.Close())
		require.NoError(t, err)
		require.Equal(t, want, fmt.Sprintf("%x", h.Sum(nil)), name)
		count++
	}
	require.Equal(t, 1712, count, "installed-file MD5 count")
	tracks := test.Collect(t, lewpath.New("Soundtrack").Glob(t.Context(), dst, "*.mp3"))
	want := 0
	if mode == "all" {
		want = 31
	}
	require.Len(t, tracks, want)
	if mode == "all" {
		name := "fg-optional-bonus-soundtrack.bin"
		data, err := lewpath.New(name).ReadFile(source)
		require.NoError(t, err)
		volume, err := parseVolume(name, data)
		require.NoError(t, err)
		for _, m := range volume.Members {
			if m.Dir {
				continue
			}
			f, err := lewpath.New(m.Path).Open(dst)
			require.NoError(t, err)
			h := crc32.New(m.crcTable)
			size, err := io.Copy(h, f)
			require.NoError(t, f.Close())
			require.NoError(t, err)
			require.Equal(t, m.Size, uint64(size), m.Path)
			require.Equal(t, m.CRC, h.Sum32(), m.Path)
		}
	}
	for _, name := range []string{"inner.fgpack", "rimworld.x3", "temp", "work", "mover"} {
		ok, err := lewpath.New(name).Exists(dst)
		require.NoError(t, err)
		require.False(t, ok, "intermediate %s remains", name)
	}
}
