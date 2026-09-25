package i3d

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestKeyConstFromOfficialPE(t *testing.T) {
	t.Parallel()
	if keyConst[0] != 0xE3E4E5E3 || keyConst[1] != 0xE3E3E3E4 {
		t.Fatalf("%#x %#x", keyConst[0], keyConst[1])
	}
}

func TestApplyRoundTrip(t *testing.T) {
	t.Parallel()
	in := makeContainer(0x2a, 7, []byte("giants-shapes-payload"))
	once, err := Apply(in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(once, in) {
		t.Fatal("cipher did not change payload")
	}
	if once[0] != in[0] || !bytes.Equal(once[1:9], in[1:9]) {
		t.Fatalf("header changed: %x vs %x", once[:9], in[:9])
	}
	twice, err := Apply(once)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(twice, in) {
		t.Fatalf("not involution\n got %x\nwant %x", twice, in)
	}
}

func TestApplyTruncated(t *testing.T) {
	t.Parallel()
	if _, err := Apply(nil); err == nil {
		t.Fatal("empty")
	}
	if _, err := Apply([]byte{1, 2, 3}); err == nil {
		t.Fatal("short record")
	}
}

func makeContainer(seed byte, idx uint32, payload []byte) []byte {
	out := []byte{seed}
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[:4], idx)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(len(payload)))
	return append(append(out, hdr[:]...), payload...)
}
