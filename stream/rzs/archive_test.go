package rzs

import (
	"io"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
)

func TestStdioIndexSize(t *testing.T) {
	for _, tt := range []struct {
		name   string
		packed uint64
		index  uint64
	}{
		{name: "fg-01.bin", packed: 0x372ad910, index: 0x372ad8fa},
		{name: "fg-02.bin", packed: 0x1dde4b95, index: 0x1dde4b7f},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := corpus.FileEnv(t, "GAROTAFITNESS_CORPUS_SOC", tt.name)
			_, err := f.Seek(31+16, io.SeekStart)
			require.NoError(t, err)
			off, n, err := parseCM(f)
			require.NoError(t, err)
			require.Equal(t, tt.index, off)
			require.Equal(t, uint64(20), n)
			idxN := tt.packed - tt.index
			require.Equal(t, uint64(22), idxN)
			idx := make([]byte, idxN)
			_, err = io.ReadFull(f, idx)
			require.NoError(t, err)
			fn := int(idx[0]) | int(idx[1])<<8 | int(idx[2])<<16
			require.Equal(t, int(idxN), 7+fn)
		})
	}
}
