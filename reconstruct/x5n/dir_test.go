package x5n

import (
	"os"
	"testing"
)

func TestParseFS25Head(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("testdata/head.bin")
	if err != nil {
		t.Fatal(err)
	}
	info, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.OldPaths) != 2 || info.OldPaths[1] != "inner.fgpack" {
		t.Fatalf("old paths %q", info.OldPaths)
	}
	if len(info.NewPaths) != 9 || info.NewPaths[1] != "shared/" {
		t.Fatalf("new paths %q", info.NewPaths)
	}
	if info.OldRefSize != 1226032094 || info.NewRefSize != 1633847662 {
		t.Fatalf("ref sizes %d %d", info.OldRefSize, info.NewRefSize)
	}
	if len(info.OldRefs) != 1 || len(info.NewRefs) != 7 || len(info.NewRefSizes) != 7 {
		t.Fatalf("refs old=%d new=%d sizes=%d", len(info.OldRefs), len(info.NewRefs), len(info.NewRefSizes))
	}
	if info.OldPaths[info.OldRefs[0]] != "inner.fgpack" {
		t.Fatalf("old ref %q", info.OldPaths[info.OldRefs[0]])
	}
}

func TestParseRejectsHDIFF13(t *testing.T) {
	t.Parallel()
	if _, err := Parse([]byte("HDIFF13&")); err == nil {
		t.Fatal("accepted HDIFF13")
	}
}
