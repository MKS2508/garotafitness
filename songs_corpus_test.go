package garotafitness

import (
	"bytes"
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
	"github.com/lucasew/garotafitness/setupdata"
	"github.com/stretchr/testify/require"
)

const socCorpus = "GAROTAFITNESS_CORPUS_SOC"

func TestSongsOfConquestSetup(t *testing.T) {
	f := corpus.FileEnv(t, socCorpus, "setup.exe")
	info, err := setupdata.Scan(f)
	require.NoError(t, err)
	require.Equal(t, "{app}\\_Redist\\fitgirl.md5", info.ManifestPath)
	require.Equal(t, 674, strings.Count(info.InstalledMD5, "\n"))
	require.Contains(t, info.Encoders, "pref")
	require.Contains(t, info.Encoders, "rzs")
	require.Contains(t, info.Encoders, "xt3u")
	require.Len(t, info.Operations, 12)
}

func TestSongsOfConquestPrefHeader(t *testing.T) {
	src := corpus.OpenEnv(t, socCorpus)
	data, err := lewpath.New("fg-optional-bonus-content.bin").ReadFile(src)
	require.NoError(t, err)
	v, err := parseVolume("fg-optional-bonus-content.bin", data)
	require.NoError(t, err)
	for s := range groupSolids(v.Members) {
		if s.pipe.String() != "pref+srep:m3yf+magic2" {
			continue
		}
		r, err := Decode(t.Context(), bytes.NewReader(data[s.off:s.off+int64(s.csz)]), s.pipe[len(s.pipe)-1])
		require.NoError(t, err)
		r2, err := Decode(t.Context(), r, s.pipe[len(s.pipe)-2])
		require.NoError(t, err)
		var head [16]byte
		n, err := io.ReadFull(r2, head[:])
		require.NoError(t, r2.Close())
		require.NoError(t, r.Close())
		require.GreaterOrEqual(t, n, 7)
		require.Equal(t, "PCF", string(head[:3]))
		require.Equal(t, []byte{0, 4, 8, 0}, head[3:7])
		return
	}
	require.FailNow(t, "no pref solid")
}

func TestSongsOfConquestPipelines(t *testing.T) {
	src := corpus.OpenEnv(t, socCorpus)
	want := map[string]Algo{
		"fg-01.bin": AlgoRZS,
		"fg-02.bin": AlgoRZS,
		"fg-03.bin": AlgoMagic2,
		"fg-04.bin": AlgoRZW,
	}
	for name, last := range want {
		t.Run(name, func(t *testing.T) {
			data, err := lewpath.New(name).ReadFile(src)
			require.NoError(t, err)
			v, err := parseVolume(name, data)
			require.NoError(t, err)
			found := false
			for _, m := range v.Members {
				if m.Dir || len(m.Pipeline) == 0 {
					continue
				}
				found = true
				require.Equal(t, last, m.Pipeline.Last().Algo, "%s (%s)", m.Path, m.Pipeline)
			}
			require.True(t, found, "no file members")
		})
	}
}

func TestExtractSongsOfConquestPref(t *testing.T) {
	src := corpus.OpenEnv(t, socCorpus)
	name := "fg-optional-bonus-content.bin"
	data, err := lewpath.New(name).ReadFile(src)
	require.NoError(t, err)
	v, err := parseVolume(name, data)
	require.NoError(t, err)
	dst := &reconstruction{files: map[string][]byte{}, dirs: map[string]fs.FileMode{}}
	found := false
	for s := range groupSolids(v.Members) {
		if !strings.Contains(s.pipe.String(), "pref") {
			continue
		}
		found = true
		require.NoError(t, extractSolid(t.Context(), Extractor{Source: src, Dest: dst}, bytes.NewReader(data), s, nil))
		for _, m := range s.files {
			if m.Dir {
				continue
			}
			b, err := dst.require(m.Path)
			require.NoError(t, err, m.Path)
			require.Equal(t, m.Size, uint64(len(b)), m.Path)
			table := m.crcTable
			if table == nil {
				table = crc32.IEEETable
			}
			require.Equal(t, m.CRC, crc32.Checksum(b, table), m.Path)
		}
	}
	require.True(t, found)
}

func TestExtractSongsOfConquestVolumes(t *testing.T) {
	src := corpus.OpenEnv(t, socCorpus)
	for _, name := range []string{"fg-01.bin", "fg-02.bin", "fg-03.bin", "fg-04.bin"} {
		t.Run(name, func(t *testing.T) {
			dst := &reconstruction{files: map[string][]byte{}, dirs: map[string]fs.FileMode{}}
			require.NoError(t, extractVolume(t.Context(), Extractor{Source: src, Dest: dst}, Volume{Name: name}, nil))
			data, err := lewpath.New(name).ReadFile(src)
			require.NoError(t, err)
			v, err := parseVolume(name, data)
			require.NoError(t, err)
			checked := 0
			for _, m := range v.Members {
				if m.Dir {
					continue
				}
				b, err := dst.require(m.Path)
				require.NoError(t, err, m.Path)
				require.Equal(t, m.Size, uint64(len(b)), m.Path)
				table := m.crcTable
				if table == nil {
					table = crc32.IEEETable
				}
				require.Equal(t, m.CRC, crc32.Checksum(b, table), m.Path)
				checked++
			}
			require.Greater(t, checked, 0)
		})
	}
}

func TestExtractSongsOfConquest(t *testing.T) {
	src := corpus.OpenEnv(t, socCorpus)
	out := t.TempDir()
	if d := os.Getenv("GAROTAFITNESS_SOC_DEST"); d != "" {
		require.NoError(t, os.MkdirAll(d, 0o755))
		out = d
	}
	dst, err := OpenDirDest(out)
	require.NoError(t, err)
	test.CloseOnCleanup(t, dst)
	require.NoError(t, (Extractor{Source: src, Dest: dst}).Extract(t.Context()))
	manifest, err := lewpath.New("_Redist/fitgirl.md5").ReadFile(dst)
	require.NoError(t, err)
	count := 0
	for line := range strings.SplitSeq(strings.TrimSpace(string(manifest)), "\n") {
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
	require.Equal(t, 674, count)
}
