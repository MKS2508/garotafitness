package pages

import (
	"bytes"
	"io"
	"testing"
)

func TestReadRoundTrip(t *testing.T) {
	t.Parallel()
	want := bytes.Repeat([]byte("abcdef"), Size) // several pages plus remainder
	buf, err := Read(bytes.NewReader(want), int64(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(buf.Release)
	got, err := io.ReadAll(buf.Reader())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d want %d", len(got), len(want))
	}
}

func TestReadZero(t *testing.T) {
	t.Parallel()
	buf, err := Read(bytes.NewReader(nil), 0)
	if err != nil {
		t.Fatal(err)
	}
	buf.Release()
	if _, err := buf.Reader().Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("err %v", err)
	}
}

func TestReadShort(t *testing.T) {
	t.Parallel()
	_, err := Read(bytes.NewReader([]byte("hi")), 8)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("err %v", err)
	}
}
