package garotafitness

import (
	"fmt"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/lucasew/garotafitness/setupdata"
	"github.com/stretchr/testify/require"
)

func TestDumpFS25OpsAndPipes(t *testing.T) {
	f := corpus.FileEnv(t, fs25Corpus, "setup.exe")
	info, err := setupdata.Scan(f)
	require.NoError(t, err)
	for i, op := range info.Operations {
		t.Logf("%02d kind=%s src=%q dst=%q filt=%q prog=%q args=%q wd=%q opt=%v",
			i, op.Kind, op.Source, op.Dest, op.Filter, op.Program, op.Args, op.WorkDir, op.Optional)
	}

	src := corpus.OpenEnv(t, fs25Corpus)
	for _, name := range []string{"fg-01.bin", "fg-02.bin", "fg-03.bin", "fg-04.bin", "fg-05.bin", "fg-06.bin", "fg-07.bin", "fg-08.bin"} {
		vol, err := src.Open(name)
		require.NoError(t, err)
		st, err := vol.Stat()
		require.NoError(t, err)
		ra := vol.(interface {
			ReadAt([]byte, int64) (int, error)
		})
		v, err := parseVolumeAt(name, ra, st.Size())
		vol.Close()
		require.NoError(t, err)
		seen := map[string]int{}
		var files int
		var bytes uint64
		for _, m := range v.Members {
			if m.Dir {
				continue
			}
			files++
			bytes += m.Size
			seen[m.Pipeline.String()]++
		}
		t.Logf("%s size=%d members=%d uncompressed=%d pipes=%v", name, st.Size(), files, bytes, seen)
	}
	fmt.Print()
}
