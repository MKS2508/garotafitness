package garotafitness

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"testing"
)

func TestToolsetMatchByNameAndHash(t *testing.T) {
	t.Parallel()
	c, err := reconstructToolset.match("fgpack.exe", "")
	if err != nil || c.id != "lzma" {
		t.Fatalf("name fallback %s %v", c.id, err)
	}
	c, err = reconstructToolset.match("fgpack.exe", "a95222984f60e3f5bea4099cab85868946523391b0e50d7f6dcc5e866d0b0dbd")
	if err != nil || c.id != "lzma" {
		t.Fatalf("rimworld %s %v", c.id, err)
	}
	c, err = reconstructToolset.match("fgpack.exe", "eb9a914ff781bc2f088e70d1b99faca73d98a96325a4a154cf52b3b52a4f860a")
	if err != nil || c.id != "i3d" {
		t.Fatalf("fs25 %s %v", c.id, err)
	}
	if _, err := reconstructToolset.match("fgpack.exe", "deadbeef"); !errors.Is(err, errUnknownToolHash) {
		t.Fatalf("unknown hash %v", err)
	}
	c, err = reconstructToolset.match("x4.exe", "7889aadec74fe2e4940a3dab081b8d560d7d751b0ed13cfc90b8986ca6ae084f")
	if err != nil || c.id != "defarm" {
		t.Fatalf("fs25 x4 %s %v", c.id, err)
	}
	if _, err := reconstructToolset.match("x4.exe", "deadbeef"); !errors.Is(err, errUnknownToolHash) {
		t.Fatalf("unknown x4 hash %v", err)
	}
}

func TestToolsetMatchByHash(t *testing.T) {
	t.Parallel()
	s := &toolset{byHash: map[string]codec{}, byName: map[string][]codec{}}
	s.add(codec{id: "lzma", sha256: "aaa", names: []string{"codec-test.exe"}})
	s.add(codec{id: "other", sha256: "bbb", names: []string{"codec-test.exe"}})
	c, err := s.match("codec-test.exe", "BBB")
	if err != nil || c.id != "other" {
		t.Fatalf("%s %v", c.id, err)
	}
	if _, err := s.match("codec-test.exe", ""); err == nil {
		t.Fatal("expected missing hash")
	}
	if _, err := s.match("codec-test.exe", "ccc"); !errors.Is(err, errUnknownToolHash) {
		t.Fatalf("err %v", err)
	}
}

func TestToolsetSameHashDifferentName(t *testing.T) {
	t.Parallel()
	const xdelta = "09763ca90c09a5f815a94527399b1f2a88685e9de462e2ff1bc5648d320e707a"
	c, err := reconstructToolset.match("xdelta3.exe", xdelta)
	if err != nil || c.id != "xdelta" {
		t.Fatalf("%s %v", c.id, err)
	}
	if g := reconstructToolset.canonical("packer.exe", xdelta); g != "x.exe" {
		t.Fatalf("%q", g)
	}
}

func TestToolsetRunByChecksum(t *testing.T) {
	t.Parallel()
	s := &toolset{byHash: map[string]codec{}, byName: map[string][]codec{}}
	s.add(codec{id: "bad", sha256: "aaa", names: []string{"codec-test.exe"}, encode: func(context.Context, []byte, []string) ([]byte, error) {
		return []byte("no"), nil
	}})
	s.add(codec{id: "good", sha256: "bbb", names: []string{"codec-test.exe"}, encode: func(context.Context, []byte, []string) ([]byte, error) {
		return []byte("ok"), nil
	}})
	want := md5sum([]byte("ok"))
	out, err := s.run(t.Context(), "codec-test.exe", "ccc", nil, nil, want)
	if err != nil || string(out) != "ok" {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := s.run(t.Context(), "codec-test.exe", "ccc", nil, nil, nil); !errors.Is(err, errUnknownToolHash) {
		t.Fatalf("err %v", err)
	}
}

func TestToolsetRunI3D(t *testing.T) {
	t.Parallel()
	in := []byte{0x2a, 0, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4}
	const fs25 = "eb9a914ff781bc2f088e70d1b99faca73d98a96325a4a154cf52b3b52a4f860a"
	out, err := reconstructToolset.run(t.Context(), "fgpack.exe", fs25, in, []string{"a.shapes", "a.fgr_"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(out, in) {
		t.Fatal("i3d did not change payload")
	}
	back, err := reconstructToolset.run(t.Context(), "fgpack.exe", fs25, out, []string{"a.fgr_", "a.shapes"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(in) {
		t.Fatalf("%x vs %x", back, in)
	}
}

func md5sum(b []byte) []byte {
	h := md5.Sum(b)
	return h[:]
}
