package garotafitness

import (
	"bytes"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/test"
	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/lucasew/garotafitness/setupdata"
	"github.com/stretchr/testify/require"
)

func TestSongsOfConquestSetupXT3U(t *testing.T) {
	f := corpus.FileEnv(t, socCorpus, "setup.exe")
	info, err := setupdata.Scan(f)
	require.NoError(t, err)
	require.Contains(t, info.Encoders, "xt3u")
	require.Contains(t, strings.ToLower(info.ArcINI), "xtool.exe decode")
}

func TestSongsOfConquestXT3UMembers(t *testing.T) {
	src := corpus.OpenEnv(t, socCorpus)
	data, err := lewpath.New("fg-03.bin").ReadFile(src)
	require.NoError(t, err)
	v, err := parseVolume("fg-03.bin", data)
	require.NoError(t, err)
	var s *solid
	for g := range groupSolids(v.Members) {
		if g.pipe.String() == "xt3u+srep:m3yf+magic2" {
			cp := g
			s = &cp
			break
		}
	}
	require.NotNil(t, s)
	require.Equal(t, AlgoXT3U, s.pipe[0].Algo)
	end := s.off + int64(s.csz)
	var r io.Reader = bytes.NewReader(data[s.off:end])
	for i := len(s.pipe) - 1; i >= 0; i-- {
		dec, err := Decode(t.Context(), r, s.pipe[i])
		require.NoError(t, err)
		test.CloseOnCleanup(t, dec)
		r = dec
	}
	checked := 0
	for _, m := range s.files {
		table := m.crcTable
		if table == nil {
			table = crc32.IEEETable
		}
		h := crc32.New(table)
		n, err := io.Copy(h, io.LimitReader(r, int64(m.Size)))
		require.NoError(t, err)
		require.Equal(t, int64(m.Size), n, m.Path)
		require.Equal(t, m.CRC, h.Sum32(), m.Path)
		checked++
	}
	require.Equal(t, len(s.files), checked)
}
