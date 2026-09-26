package garotafitness

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
)

func TestFS25Fg01FirstMember(t *testing.T) {
	skipHeavySolid(t)
	src := corpus.OpenEnv(t, fs25Corpus)
	vol, err := src.Open("fg-01.bin")
	require.NoError(t, err)
	defer vol.Close()
	st, err := vol.Stat()
	require.NoError(t, err)
	ra := vol.(interface {
		ReadAt([]byte, int64) (int, error)
	})
	v, err := parseVolumeAt("fg-01.bin", ra, st.Size())
	require.NoError(t, err)
	var s *solid
	for g := range groupSolids(v.Members) {
		if len(g.pipe) > 0 && g.pipe[0].Algo == AlgoXT2PNG {
			cp := g
			s = &cp
			break
		}
	}
	require.NotNil(t, s)
	require.NotEmpty(t, s.files)
	m := s.files[0]
	t.Logf("first %s size=%d crc=%08x pipe=%s", m.Path, m.Size, m.CRC, s.pipe)
	for i, f := range s.files {
		if i >= 5 {
			break
		}
		t.Logf("  [%d] %s %d", i, f.Path, f.Size)
	}

	var r io.Reader = io.NewSectionReader(ra, s.off, int64(s.csz))
	var closers []io.Closer
	t.Cleanup(func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i].Close()
		}
	})
	for i := len(s.pipe) - 1; i >= 0; i-- {
		dec, err := Decode(t.Context(), r, s.pipe[i])
		require.NoError(t, err, s.pipe[i])
		closers = append(closers, dec)
		r = dec
	}
	table := m.crcTable
	if table == nil {
		table = crc32.IEEETable
	}
	h := crc32.New(table)
	n, err := io.Copy(h, io.LimitReader(r, int64(m.Size)))
	require.NoError(t, err)
	require.Equal(t, int64(m.Size), n, m.Path)
	require.Equal(t, m.CRC, h.Sum32(), m.Path)
}

func TestFS25Fg01PastFirstStream(t *testing.T) {
	skipHeavySolid(t)
	src := corpus.OpenEnv(t, fs25Corpus)
	vol, err := src.Open("fg-01.bin")
	require.NoError(t, err)
	defer vol.Close()
	st, err := vol.Stat()
	require.NoError(t, err)
	ra := vol.(interface {
		ReadAt([]byte, int64) (int, error)
	})
	v, err := parseVolumeAt("fg-01.bin", ra, st.Size())
	require.NoError(t, err)
	var s *solid
	for g := range groupSolids(v.Members) {
		if len(g.pipe) > 0 && g.pipe[0].Algo == AlgoXT2PNG {
			cp := g
			s = &cp
			break
		}
	}
	require.NotNil(t, s)

	var r io.Reader = io.NewSectionReader(ra, s.off, int64(s.csz))
	var closers []io.Closer
	t.Cleanup(func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i].Close()
		}
	})
	for i := len(s.pipe) - 1; i >= 0; i-- {
		dec, err := Decode(t.Context(), r, s.pipe[i])
		require.NoError(t, err, s.pipe[i])
		closers = append(closers, dec)
		r = dec
	}

	const past = 10509958 + 28 + 4096
	var off uint64
	checked := 0
	for _, m := range s.files {
		table := m.crcTable
		if table == nil {
			table = crc32.IEEETable
		}
		h := crc32.New(table)
		n, err := io.Copy(h, io.LimitReader(r, int64(m.Size)))
		require.NoError(t, err, m.Path)
		require.Equal(t, int64(m.Size), n, m.Path)
		require.Equal(t, m.CRC, h.Sum32(), m.Path)
		off += m.Size
		checked++
		if off > past {
			break
		}
	}
	t.Logf("checked %d files through offset %d", checked, off)
	require.Greater(t, checked, 1)
}

func TestFS25Fg01FlagDePNGMembers(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	vol, err := src.Open("fg-01.bin")
	require.NoError(t, err)
	defer vol.Close()
	st, err := vol.Stat()
	require.NoError(t, err)
	ra := vol.(interface {
		ReadAt([]byte, int64) (int, error)
	})
	v, err := parseVolumeAt("fg-01.bin", ra, st.Size())
	require.NoError(t, err)
	var s *solid
	for g := range groupSolids(v.Members) {
		if len(g.pipe) > 0 && g.pipe[0].Algo == AlgoXT2PNG {
			cp := g
			s = &cp
			break
		}
	}
	require.NotNil(t, s)
	hit := -1
	for i, m := range s.files {
		if m.Path == "web_data/img/icons/flag-de.png" {
			hit = i
			break
		}
	}
	require.GreaterOrEqual(t, hit, 0, "flag-de.png not in fg-01 xt2png solid")
	var uncomp uint64
	for i, m := range s.files {
		if i >= hit-8 && i <= hit+3 {
			t.Logf("[%d] %s size=%d crc=%08x uncompOff=%d", i, m.Path, m.Size, m.CRC, uncomp)
		}
		uncomp += m.Size
	}
	t.Logf("solid members=%d compressed=%d uncompressed=%d flag-de index=%d", len(s.files), s.csz, uncomp, hit)
}

func TestFS25Fg01DecodeUntilFlagDe(t *testing.T) {
	skipHeavySolid(t)
	src := corpus.OpenEnv(t, fs25Corpus)
	vol, err := src.Open("fg-01.bin")
	require.NoError(t, err)
	defer vol.Close()
	st, err := vol.Stat()
	require.NoError(t, err)
	ra := vol.(interface {
		ReadAt([]byte, int64) (int, error)
	})
	v, err := parseVolumeAt("fg-01.bin", ra, st.Size())
	require.NoError(t, err)
	var s *solid
	for g := range groupSolids(v.Members) {
		if len(g.pipe) > 0 && g.pipe[0].Algo == AlgoXT2PNG {
			cp := g
			s = &cp
			break
		}
	}
	require.NotNil(t, s)
	var r io.Reader = io.NewSectionReader(ra, s.off, int64(s.csz))
	var closers []io.Closer
	t.Cleanup(func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i].Close()
		}
	})
	for i := len(s.pipe) - 1; i >= 0; i-- {
		dec, err := Decode(t.Context(), r, s.pipe[i])
		require.NoError(t, err, s.pipe[i])
		closers = append(closers, dec)
		r = dec
	}
	outDir := "/tmp/xt2png-members"
	require.NoError(t, os.MkdirAll(outDir, 0o755))
	for i, m := range s.files {
		dst := io.Writer(io.Discard)
		var buf bytes.Buffer
		if i >= 42765 {
			dst = &buf
		}
		n, err := io.Copy(dst, io.LimitReader(r, int64(m.Size)))
		require.NoError(t, err, "member[%d] %s size=%d copied=%d", i, m.Path, m.Size, n)
		require.Equal(t, int64(m.Size), n, "member[%d] %s", i, m.Path)
		if i >= 42765 {
			name := filepath.Base(m.Path)
			require.NoError(t, os.WriteFile(filepath.Join(outDir, fmt.Sprintf("%05d-%s", i, name)), buf.Bytes(), 0o644))
		}
		if m.Path == "web_data/img/icons/flag-de.png" {
			t.Logf("flag-de.png decoded ok n=%d", n)
			return
		}
	}
	require.FailNow(t, "flag-de.png not reached")
}
