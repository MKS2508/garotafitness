package garotafitness

import (
	"os"
	"strings"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/lucasew/garotafitness/setupdata"
	"github.com/stretchr/testify/require"
)

const fs25Corpus = "GAROTAFITNESS_CORPUS_FS25"

func skipHeavySolid(t *testing.T) {
	t.Helper()
	if os.Getenv("GAROTAFITNESS_HEAVY") == "" {
		t.Skip("set GAROTAFITNESS_HEAVY=1 to decode large FS25 solids")
	}
}

func TestFarmingSimulator25Setup(t *testing.T) {
	f := corpus.FileEnv(t, fs25Corpus, "setup.exe")
	info, err := setupdata.Scan(f)
	require.NoError(t, err)
	require.Equal(t, "{app}\\_Redist\\fitgirl.md5", info.ManifestPath)
	require.Equal(t, 39796, strings.Count(info.InstalledMD5, "\n"))
	require.Contains(t, info.Encoders, "xt2png")
	require.Contains(t, info.Encoders, "srep")
	require.Contains(t, info.Encoders, "magic2")
	require.Len(t, info.Operations, 56)
}

func TestFarmingSimulator25Pipelines(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	want := map[string]Algo{
		"fg-03.bin": AlgoRZS,
		"fg-04.bin": AlgoRZS,
		"fg-06.bin": AlgoRZS,
		"fg-07.bin": AlgoRZS,
		"fg-08.bin": AlgoRZS,
	}
	for name, last := range want {
		t.Run(name, func(t *testing.T) {
			f, err := src.Open(name)
			require.NoError(t, err)
			st, err := f.Stat()
			require.NoError(t, err)
			v, err := parseVolumeAt(name, f.(interface {
				ReadAt([]byte, int64) (int, error)
			}), st.Size())
			f.Close()
			require.NoError(t, err)
			found := false
			for _, m := range v.Members {
				if m.Dir || len(m.Pipeline) == 0 {
					continue
				}
				found = true
				if m.Pipeline.Last().Algo != last {
					t.Fatalf("%s last %s want %s (%s)", m.Path, m.Pipeline.Last().Algo, last, m.Pipeline)
				}
			}
			require.True(t, found)
		})
	}
}

func TestFarmingSimulator25XT2PNGNamed(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	f, err := src.Open("fg-01.bin")
	require.NoError(t, err)
	st, err := f.Stat()
	require.NoError(t, err)
	v, err := parseVolumeAt("fg-01.bin", f.(interface {
		ReadAt([]byte, int64) (int, error)
	}), st.Size())
	f.Close()
	require.NoError(t, err)
	found := false
	for _, m := range v.Members {
		if m.Dir || len(m.Pipeline) == 0 {
			continue
		}
		require.Equal(t, AlgoXT2PNG, m.Pipeline[0].Algo, m.Pipeline.String())
		found = true
		break
	}
	require.True(t, found)
}

func TestFarmingSimulator25Fg07(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	out := t.TempDir()
	dst, err := OpenDirDest(out)
	require.NoError(t, err)
	t.Cleanup(func() { dst.Close() })
	require.NoError(t, extractVolume(t.Context(), Extractor{Source: src, Dest: dst}, Volume{Name: "fg-07.bin"}, nil))
	b, err := os.ReadFile(out + "/new.x5n")
	require.NoError(t, err)
	require.Greater(t, len(b), 100)
	require.Equal(t, "HDIFF19", string(b[:7]))
}
