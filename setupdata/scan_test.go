package setupdata

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
	ulzma "github.com/ulikunitz/xz/lzma"
)

func TestScanNil(t *testing.T) {
	t.Parallel()
	_, err := Scan(nil)
	require.ErrorIs(t, err, errNil)
}

func TestScanPlain(t *testing.T) {
	t.Parallel()
	in := []byte("" +
		"[External compressor:srep]\r\n" +
		"unpackcmd = srep d\r\n" +
		"\r\n" +
		"[External compressor:mpzz]\r\n" +
		"header = 0\r\n")
	info, err := Scan(bytes.NewReader(in))
	require.NoError(t, err)
	require.Contains(t, info.Encoders, "srep")
	require.Contains(t, info.Encoders, "mpzz")
	require.Contains(t, info.ArcINI, "[External compressor:srep]")
}

func TestScanZLB(t *testing.T) {
	t.Parallel()
	plain := []byte("" +
		"[External compressor:rzw]\r\n" +
		"unpackcmd = rzw d f2 f1 128 128\r\n")
	info, err := Scan(bytes.NewReader(packZLB(t, plain)))
	require.NoError(t, err)
	require.Contains(t, info.Encoders, "rzw")
	require.Contains(t, info.ArcINI, "[External compressor:rzw]")
}

func TestScanCorpus(t *testing.T) {
	t.Parallel()
	f := corpus.File(t, "setup.exe")
	info, err := Scan(f)
	require.NoError(t, err)
	require.Equal(t, 1712, strings.Count(info.InstalledMD5, "\n"))
	require.NotEmpty(t, info.Encoders)
	require.Contains(t, info.Encoders, "srep")
	require.True(t, hasAny(info.Encoders, "mpzz", "magic2", "rzw"))
	require.Contains(t, info.ArcINI, "[External compressor:")
}

func packZLB(t *testing.T, plain []byte) []byte {
	t.Helper()
	const dict = 1 << 16
	var buf bytes.Buffer
	buf.WriteString(zlbMagic)
	buf.WriteByte(8) // LZMA2 prop for 64 KiB
	w, err := ulzma.Writer2Config{DictCap: dict}.NewWriter2(&buf)
	require.NoError(t, err)
	_, err = w.Write(plain)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func hasAny(got []string, want ...string) bool {
	for _, g := range got {
		for _, w := range want {
			if g == w {
				return true
			}
		}
	}
	return false
}

func TestInstalledManifestEncoding(t *testing.T) {
	prefix := "900150983cd24fb0d6963f7d28e17f72 *..\\Data\\"
	for _, tt := range []struct {
		name    string
		encoded []byte
		want    string
	}{
		{"UTF8", []byte(prefix + "Я.txt\r\n"), prefix + "Я.txt\r\n"},
		{"Windows1251", append([]byte(prefix), []byte{0xdf, '.', 't', 'x', 't', '\r', '\n'}...), prefix + "Я.txt\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := append([]byte("\x00unrelated\x00"), tt.encoded...)
			require.Equal(t, tt.want, installedMD5(input))
		})
	}
	require.Empty(t, installedMD5([]byte("900150983cd24fb0d6963f7d28e17f72 *..\\truncated")))
}
