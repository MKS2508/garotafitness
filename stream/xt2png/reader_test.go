package xt2png

import (
	"bytes"
	"os"
	"testing"
)

func TestFS25FirstChunkRestore(t *testing.T) {
	raw, err := os.ReadFile("testdata/fg01.head.bin")
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHeader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	rest := raw[headerLen(h):]
	sc := i32le(rest)
	bs := i64le(rest[4:])
	if sc != 3 || bs != 91 {
		t.Fatalf("sc=%d bs=%d", sc, bs)
	}
	rest = rest[12:]
	r := &reader{ctx: t.Context(), hdr: h}
	var got int
	off := 0
	for i := 0; i < 3; i++ {
		sh, err := readStreamHeader(bytes.NewReader(rest[i*18:]))
		if err != nil {
			t.Fatal(err)
		}
		payload := rest[3*18+off : 3*18+off+int(sh.NewSize)]
		off += int(sh.NewSize)
		rawp, ext, err := r.takeStreamFrom(sh, payload)
		if err != nil {
			t.Fatal(i, err)
		}
		out, err := r.restore(sh, rawp, ext)
		if err != nil {
			t.Fatal(i, err)
		}
		if int32(len(out)) != sh.OldSize {
			t.Fatalf("stream %d got %d want %d", i, len(out), sh.OldSize)
		}
		got += len(out)
	}
	if got != 28+17+23 {
		t.Fatalf("restored %d", got)
	}
}

func (r *reader) takeStreamFrom(h streamHeader, payload []byte) (raw, ext []byte, err error) {
	r.block = payload
	r.blockOff = 0
	return r.takeStream(h)
}
