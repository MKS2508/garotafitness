package x4

import (
	"testing"
)

func TestPackPadsTo8(t *testing.T) {
	t.Parallel()
	out, err := Pack([]File{{Name: "n/a.txt", Data: []byte("hi")}}, "02", "01")
	if err != nil {
		t.Fatal(err)
	}
	if len(out)%8 != 0 || len(out) < 8 {
		t.Fatalf("len %d", len(out))
	}
}
func TestPackRejectsVersion(t *testing.T) {
	t.Parallel()
	if _, err := Pack(nil, "01", "01"); err == nil {
		t.Fatal("accepted")
	}
}
