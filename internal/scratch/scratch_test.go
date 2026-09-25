package scratch

import (
	"strings"
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/test"
)

func TestMkdirTempUsesWithDir(t *testing.T) {
	t.Parallel()
	dest := t.TempDir()
	parent, err := lewpath.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	test.CloseOnCleanup(t, parent)
	ctx := WithDir(t.Context(), dest)
	d, err := MkdirTemp(ctx, "x5n-")
	if err != nil {
		t.Fatal(err)
	}
	rel := d.Rel().String()
	if !strings.HasPrefix(rel, "tmp/") || !strings.Contains(rel, "x5n-") {
		t.Fatalf("pattern %s", d.Rel())
	}
	ok, err := d.Rel().IsDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("%s not a directory under dest", d.Rel())
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	ok, err = d.Rel().Exists(parent)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("temp dir still present")
	}
}

func TestMkdirTempRequiresWithDir(t *testing.T) {
	t.Parallel()
	if _, err := MkdirTemp(t.Context(), "x5n-"); err == nil {
		t.Fatal("expected error")
	}
}
