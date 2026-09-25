package mpzz

import (
	"bytes"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/lucasew/garotafitness/stream/srep"
)

// fg-01 after SREP: testdata/header.hex.
var fg01Head = []byte{
	'O', 'G', 'G', 'R', 'E', 0x00, 0x09, 0xf9,
	0x12, 0x8c, 0xaa, 0xb3, 0xee, 0xae, 0x5c, 0xde,
}

const (
	fg01InnerSize = 255994514
	fg01InnerCRC  = 0xf7a300d7
	fg01SolidOff  = 0x1F
)

func TestNewReader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   io.Reader
		want error
	}{
		{name: "nil", want: errNil},
		{name: "empty", in: bytes.NewReader(nil), want: io.EOF},
		{name: "short", in: bytes.NewReader([]byte("OGG")), want: io.ErrUnexpectedEOF},
		{name: "arc", in: bytes.NewReader([]byte("ArC\x01x")), want: errMagic},
		{name: "ogg", in: bytes.NewReader([]byte("OggS\x00")), want: errMagic},
		{name: "ver", in: bytes.NewReader([]byte("OGGRE\x01\x09")), want: errVersion},
		{name: "stat", in: bytes.NewReader([]byte("OGGRE\x00\x04")), want: errFlags},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rc, err := NewReader(t.Context(), tt.in)
			if rc != nil {
				t.Fatalf("NewReader(ctx, %s) reader = %T; want nil", tt.name, rc)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("NewReader(ctx, %s) err = %v; want %v", tt.name, err, tt.want)
			}
		})
	}
}

func TestSlurpReaderAt(t *testing.T) {
	t.Parallel()
	want := []byte("OGGRE\x00\x09hello")
	got, err := slurp(bytes.NewReader(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReaderAt slurp %q; want %q", got, want)
	}
	got, err = slurp(io.LimitReader(bytes.NewReader(want), int64(len(want))))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadAll slurp %q; want %q", got, want)
	}
}

func TestNewReaderOGGRE(t *testing.T) {
	t.Parallel()
	rc, err := NewReader(t.Context(), bytes.NewReader(fg01Head))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rc.Close() })
	n, err := rc.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated command: n=%d err=%v", n, err)
	}
}

func TestHeaderHex(t *testing.T) {
	t.Parallel()
	raw, err := lewpath.New("header.hex").ReadFile(testdataRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	var hexDigits strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		hexDigits.WriteString(strings.Map(func(r rune) rune {
			if strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return r
			}
			return -1
		}, line))
	}
	got, err := hex.DecodeString(hexDigits.String())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fg01Head) {
		t.Fatalf("testdata/header.hex = %x; want %x", got, fg01Head)
	}
}

func TestNewReaderCorpus(t *testing.T) {
	t.Parallel()
	f := corpus.File(t, "fg-01.bin")
	if _, err := f.Seek(fg01SolidOff, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	sr, err := srep.NewReader(t.Context(), f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sr.Close() })
	rc, err := NewReader(t.Context(), sr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rc.Close() })
	h := crc32.New(crc32.MakeTable(0x0895171b))
	n, err := io.Copy(h, rc)
	if err != nil {
		t.Fatal(err)
	}
	if n != fg01InnerSize {
		t.Fatalf("size %d; want %d", n, fg01InnerSize)
	}
	got := h.Sum32()
	if got != fg01InnerCRC {
		t.Fatalf("crc32 %08x; want %08x", got, fg01InnerCRC)
	}
}
