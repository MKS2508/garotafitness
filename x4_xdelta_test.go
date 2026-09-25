package garotafitness

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/lucasew/garotafitness/reconstruct/x4"
	"github.com/lucasew/garotafitness/reconstruct/xdelta"
	"github.com/stretchr/testify/require"
)

// Smallest FS25 pack+patch pair, vendored under testdata/ after one harvest.
// Rebuilding still walks the fg-01 solid (~49GiB uncompressed); do not do that
// from ordinary go test.
const x4FixturePack = "extraContentNewHollandCR11"

func TestFS25X4XdeltaStep(t *testing.T) {
	files := loadX4Fixture(t, x4FixturePack)
	var pack []x4.File
	var patch []byte
	prefix := "pdlc/" + x4FixturePack + "/"
	for name, b := range files {
		switch {
		case strings.EqualFold(name, "pdlc/"+x4FixturePack+".dlc.x"):
			patch = b
		case strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)):
			pack = append(pack, x4.File{Name: strings.TrimPrefix(name, prefix), Data: b})
		}
	}
	require.NotEmpty(t, pack)
	require.NotEmpty(t, patch)
	t.Logf("pack files=%d patch=%d", len(pack), len(patch))

	dlc, err := x4.Pack(pack, "02", "01")
	require.NoError(t, err)
	t.Logf("x4 out=%d", len(dlc))

	_, err = xdelta.Apply(t.Context(), dlc, patch)
	require.NoError(t, err, "x4 output must be a valid xdelta source for the FitGirl patch")
}

func loadX4Fixture(t *testing.T, pack string) map[string][]byte {
	t.Helper()
	dirs := []string{
		filepath.Join("testdata", "x4-"+pack),
		filepath.Join("/media/ssd1tb/garotafitness/fixtures", "x4-"+pack),
	}
	for _, dir := range dirs {
		if files := readX4Fixture(dir); len(files) > 0 {
			return files
		}
	}
	if os.Getenv("GAROTAFITNESS_HARVEST") == "" {
		t.Skip("missing testdata/x4-" + pack + "; set GAROTAFITNESS_HARVEST=1 to rebuild from fg-01.bin")
	}
	dir := dirs[0]
	t.Logf("harvesting %s from fg-01.bin into %s", pack, dir)
	files := harvestFg01(t, func(p string) bool {
		return strings.Contains(strings.ToLower(p), strings.ToLower(pack))
	})
	require.NotEmpty(t, files)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	for name, b := range files {
		dst := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
		require.NoError(t, os.WriteFile(dst, b, 0o644))
	}
	return files
}

func readX4Fixture(dir string) map[string][]byte {
	if _, err := os.Stat(dir); err != nil {
		return nil
	}
	out := map[string][]byte{}
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = b
		return nil
	})
	return out
}

func harvestFg01(t *testing.T, keep func(string) bool) map[string][]byte {
	t.Helper()
	src := corpus.OpenEnv(t, fs25Corpus)
	f, err := src.Open("fg-01.bin")
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	st, err := f.Stat()
	require.NoError(t, err)
	ra, ok := f.(io.ReaderAt)
	require.True(t, ok)
	parsed, err := parseVolumeAt("fg-01.bin", ra, st.Size())
	require.NoError(t, err)
	var s *solid
	for g := range groupSolids(parsed.Members) {
		cp := g
		s = &cp
		break
	}
	require.NotNil(t, s)
	r := io.Reader(io.NewSectionReader(ra, s.off, int64(s.csz)))
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
	out := map[string][]byte{}
	for _, m := range s.files {
		if keep(m.Path) {
			b := make([]byte, m.Size)
			_, err := io.ReadFull(r, b)
			require.NoError(t, err, m.Path)
			out[m.Path] = b
			t.Logf("kept %s %d", m.Path, len(b))
			continue
		}
		_, err := io.CopyN(io.Discard, r, int64(m.Size))
		require.NoError(t, err, m.Path)
	}
	return out
}
