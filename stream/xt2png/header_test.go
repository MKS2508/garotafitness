package xt2png

import (
	"bytes"
	"os"
	"testing"
)

func TestParseFS25Header(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/fg01.head.bin")
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHeader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if h.Depth != 2 || h.Method != "png+preflate" {
		t.Fatalf("depth=%d method=%q", h.Depth, h.Method)
	}
	if len(h.Resources) != 8 {
		t.Fatalf("resources %d", len(h.Resources))
	}
	if h.Compressed != 0 || len(h.Dups) != 0 {
		t.Fatalf("flag=%d dups=%d", h.Compressed, len(h.Dups))
	}
	rest := raw[headerLen(h):]
	sc, rest := i32le(rest), rest[4:]
	bs, rest := i64le(rest), rest[8:]
	if sc != 3 || bs != 91 {
		t.Fatalf("chunk sc=%d bs=%d", sc, bs)
	}
	var sum int32
	for i := 0; i < 3; i++ {
		sh, err := readStreamHeader(bytes.NewReader(rest[i*18:]))
		if err != nil {
			t.Fatal(err)
		}
		if sh.Kind != kindExtended {
			t.Fatalf("stream %d kind %d", i, sh.Kind)
		}
		if getBits(sh.Option, 0, 3) != subPreflate {
			t.Fatalf("stream %d sub %d", i, getBits(sh.Option, 0, 3))
		}
		sum += sh.NewSize
	}
	if int64(sum) != bs {
		t.Fatalf("sumNew %d bs %d", sum, bs)
	}
	tail := i32le(rest[3*18+int(bs):])
	if tail != 10509958 {
		t.Fatalf("first tail %d", tail)
	}
}

func headerLen(h Header) int {
	n := 4 + 16 + 4 + 1 + len(h.Method) + 4
	for _, r := range h.Resources {
		n += 1 + len(r.Name) + 4 + len(r.Data)
	}
	n++ // flag
	return n
}

func i32le(b []byte) int32 {
	return int32(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)
}

func i64le(b []byte) int64 {
	return int64(uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56)
}
