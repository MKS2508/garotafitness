package garotafitness

import (
	"io"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
)

func TestFS25ExtractSmallVolumes(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	for _, name := range []string{"fg-03.bin", "fg-04.bin", "fg-06.bin", "fg-07.bin", "fg-08.bin"} {
		t.Run(name, func(t *testing.T) {
			out := t.TempDir()
			dst, err := OpenDirDest(out)
			require.NoError(t, err)
			t.Cleanup(func() { dst.Close() })
			require.NoError(t, extractVolume(t.Context(), Extractor{Source: src, Dest: dst}, Volume{Name: name}, nil))
		})
	}
}

func TestFS25ExtractFirstFiles(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	for _, name := range []string{"fg-02.bin", "fg-05.bin"} {
		t.Run(name, func(t *testing.T) {
			vol, err := src.Open(name)
			require.NoError(t, err)
			st, err := vol.Stat()
			require.NoError(t, err)
			ra := vol.(interface {
				ReadAt([]byte, int64) (int, error)
			})
			v, err := parseVolumeAt(name, ra, st.Size())
			require.NoError(t, err)
			var s *solid
			for g := range groupSolids(v.Members) {
				cp := g
				s = &cp
				break
			}
			require.NotNil(t, s)
			t.Logf("%s pipe=%s files=%d first=%s size=%d", name, s.pipe, len(s.files), s.files[0].Path, s.files[0].Size)

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
			n := 3
			if len(s.files) < n {
				n = len(s.files)
			}
			// fg-02 is one 1GiB file; only read a prefix to prove the decoder opens.
			if name == "fg-02.bin" {
				buf := make([]byte, 64)
				_, err := io.ReadFull(r, buf)
				require.NoError(t, err)
				t.Logf("fg-02 head %x", buf[:16])
				return
			}
			checked := 0
			for _, m := range s.files[:n] {
				got, err := io.ReadAll(io.LimitReader(r, int64(m.Size)))
				require.NoError(t, err, m.Path)
				require.Equal(t, int(m.Size), len(got), m.Path)
				checked++
			}
			require.Equal(t, n, checked)
		})
	}
}
