package garotafitness

import (
	"bytes"
	"encoding/hex"
	"hash/crc32"
	"io/fs"
	"strings"
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArchiveDescriptorCRC(t *testing.T) {
	// The real fg-05 footer descriptor, including its custom CRC at the end.
	raw, err := hex.DecodeString("41724301086c7a6d613a6d666274343a64316d006278a0d4e6fdaa1828fb")
	require.NoError(t, err)
	d, err := parseLocal(raw)
	require.NoError(t, err)
	require.Same(t, fitgirlCRCTable, d.table)
	standard := bytes.Clone(raw)
	crc := crc32.ChecksumIEEE(standard[:len(standard)-4])
	for i := 0; i < 4; i++ {
		standard[len(standard)-4+i] = byte(crc >> (8 * i))
	}
	d, err = parseLocal(standard)
	require.NoError(t, err)
	require.Same(t, crc32.IEEETable, d.table)
	for i := range raw {
		bad := bytes.Clone(raw)
		bad[i] ^= 1
		_, err := parseLocal(bad)
		require.Error(t, err, "corrupt descriptor accepted at %d", i)
	}
}

func TestExtractDecodedVolumes(t *testing.T) {
	src := corpus.Open(t)
	for _, name := range []string{"fg-01.bin", "fg-02.bin", "fg-03.bin", "fg-04.bin", "fg-05.bin", "fg-06.bin"} {
		t.Run(name, func(t *testing.T) {
			ok, err := lewpath.New(name).Exists(src)
			if err != nil || !ok {
				t.Skip("corpus not mounted")
			}
			dst := &reconstruction{files: map[string][]byte{}, dirs: map[string]fs.FileMode{}}
			e := Extractor{Source: src, Dest: dst}
			require.NoError(t, extractVolume(t.Context(), e, Volume{Name: name}, nil))
		})
	}
}

func TestPackedRoundTripSmall(t *testing.T) {
	t.Parallel()
	// 0x06 → type 3 (DIR)
	v, n, err := readPacked([]byte{0x06}, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(3), v)
	require.Equal(t, 1, n)
}

func TestParseCorpusVolumes(t *testing.T) {
	src := corpus.Open(t)
	cases := []struct {
		file   string
		member string
		method string
		last   Algo
	}{
		{"fg-01.bin", "inner.fgpack", "mpzz+srep:m3f:mem228mb", AlgoSREP},
		{"fg-04.bin", "inner.fgpack.x5", "srep:m3yf+4x4:b128mb:rzw", Algo4x4},
		{"fg-06.bin", "steam_appid.txt", "magic2", AlgoMagic2},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := lewpath.New(tc.file).ReadFile(src)
			require.NoError(t, err)
			v, err := parseVolume(tc.file, data)
			require.NoError(t, err)
			found := false
			for _, m := range v.Members {
				if strings.Contains(m.Path, tc.member) {
					found = true
					require.Equal(t, tc.method, m.Pipeline.String())
					require.Equal(t, tc.last, m.Pipeline.Last().Algo)
				}
			}
			require.True(t, found, "missing member %s in %+v", tc.member, v.Members)
		})
	}
}

func TestPipelineInventory(t *testing.T) {
	src := corpus.Open(t)
	seen := map[string]Algo{}
	for p, err := range lewpath.New(".").IterDir(src) {
		require.NoError(t, err)
		name := p.Name()
		if !strings.HasPrefix(name, "fg-") || !strings.HasSuffix(name, ".bin") {
			continue
		}
		data, err := p.ReadFile(src)
		require.NoError(t, err)
		v, err := parseVolume(name, data)
		require.NoError(t, err, name)
		for _, m := range v.Members {
			if m.Dir || len(m.Pipeline) == 0 {
				continue
			}
			s := m.Pipeline.String()
			if _, ok := seen[s]; ok {
				continue
			}
			last := m.Pipeline.Last()
			seen[s] = last.Algo
			t.Logf("%s %s last=%s", name, s, last.Algo)
			assert.True(t, last.Known(), "%s: unknown last atom %s", name, last)
		}
	}
	require.NotEmpty(t, seen)
}
