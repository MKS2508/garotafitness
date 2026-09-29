// TestFG06Direct probes the kernel directly via DecodeBytes (one shot
// on the full body) to verify whether the fg06SHA256 hardcoded in
// reader_test.go is still achievable with the current magic2dec.wasm.
// This diagnostic test will be removed once the SHA is reconciled with
// the streaming reader's actual output.
package magic2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/lucasew/garotafitness/internal/corpus"
)

func TestFG06Direct(t *testing.T) {
	f := corpus.File(t, "fg-06.bin")
	_, err := f.Seek(31, io.SeekStart)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 93116)
	if _, err := io.ReadFull(f, data); err != nil {
		t.Fatal(err)
	}

	body2 := data[headerLen:]
	direct, err := DecodeBytes(context.Background(), body2)
	if err != nil {
		t.Logf("DecodeBytes error: %v", err)
		return
	}
	sum := sha256.Sum256(direct)
	t.Logf("DIRECT: len=%d sha=%s first16=%v", len(direct), hex.EncodeToString(sum[:]), direct[:16])

	streaming := newReaderForTest(t, data)
	streamed, err := streaming()
	if err != nil {
		t.Fatal(err)
	}
	defer streamed.Close()

	out := make([]byte, 1<<20)
	collected := make([]byte, 0, 1<<20)
	for {
		n, err := streamed.Read(out)
		if n > 0 {
			collected = append(collected, out[:n]...)
		}
		if err != nil {
			break
		}
	}
	sum2 := sha256.Sum256(collected)
	t.Logf("STREAMING: len=%d sha=%s first16=%v", len(collected), hex.EncodeToString(sum2[:]), collected[:16])
}

func newReaderForTest(t *testing.T, data []byte) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return NewReader(context.Background(), bytesReader(data))
	}
}

func bytesReader(b []byte) io.Reader {
	return &byteSliceReader{data: b}
}

type byteSliceReader struct {
	data []byte
	pos  int
}

func (b *byteSliceReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}