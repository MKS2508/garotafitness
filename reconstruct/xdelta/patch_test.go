package xdelta

import (
	"bytes"
	"encoding/binary"
	"hash/adler32"
	"testing"
)

func literalPatch(data []byte) []byte {
	// VCDIFF, one checksummed window, ADD with explicit size, no source.
	b := []byte{0xd6, 0xc3, 0xc4, 0, 0, 4, byte(11 + len(data)), byte(len(data)), 0, byte(len(data)), 2, 0}
	b = binary.BigEndian.AppendUint32(b, adler32.Checksum(data))
	b = append(b, data...)
	return append(b, 1, byte(len(data)))
}

func TestApplyStreamMatchesMemory(t *testing.T) {
	want := []byte("hello, patch")
	patch := literalPatch(want)
	var buf bytes.Buffer
	err := ApplyStream(t.Context(), bytes.NewReader(nil), 0, bytes.NewReader(patch), int64(len(patch)), SeqWriter(&buf))
	if err != nil || !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("%q %v", buf.Bytes(), err)
	}
}

func TestApplyWindowChecksum(t *testing.T) {
	want := []byte("hello, patch")
	patch := literalPatch(want)
	got, err := Apply(t.Context(), nil, patch)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%q %v", got, err)
	}
	bad := bytes.Clone(patch)
	bad[12] ^= 1
	if _, err := Apply(t.Context(), nil, bad); err == nil {
		t.Fatal("accepted bad window checksum")
	}
	for n := 5; n < len(patch); n++ {
		if _, err := targetSize(patch[:n]); err == nil {
			t.Fatalf("accepted truncated envelope at %d", n)
		}
	}
}

func TestTargetSizeBounds(t *testing.T) {
	for _, b := range [][]byte{
		{}, {0xd6, 0xc3, 0xc4, 0, 1},
		{0xd6, 0xc3, 0xc4, 0, 4, 0xff, 0xff, 0xff, 0xff, 0x7f},
		{0xd6, 0xc3, 0xc4, 0, 0, 3},
	} {
		if _, err := targetSize(b); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
}
