package garotafitness

import (
	"hash/crc32"
	"io"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
)

func TestFS25Fg01FirstMember(t *testing.T) {
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
