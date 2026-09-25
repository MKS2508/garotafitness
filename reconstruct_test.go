package garotafitness

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/lewtec/lewkit/x/test"
	"github.com/lucasew/garotafitness/internal/scratch"
)

func TestInstalledChecksums(t *testing.T) {
	s := &reconstruction{files: map[string][]byte{"Data/a.txt": []byte("abc")}}
	manifest := "900150983cd24fb0d6963f7d28e17f72 *..\\Data\\a.txt\r\n"
	if err := s.verifyInstalled(t.Context(), manifest, "_Redist"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"", "not a checksum\n", strings.Replace(manifest, "9001", "0001", 1),
		strings.Replace(manifest, "a.txt", "missing", 1),
		strings.Replace(manifest, "Data\\a.txt", "..\\escape", 1),
		strings.Replace(manifest, "Data\\a.txt", "C:\\escape", 1),
	} {
		if err := s.verifyInstalled(t.Context(), bad, "_Redist"); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.verifyInstalled(ctx, manifest, "_Redist"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestStagingRejectsEscapes(t *testing.T) {
	s := &reconstruction{files: map[string][]byte{}}
	for _, name := range []string{"../escape", "/escape"} {
		if _, err := s.Create(name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	if len(s.files) != 0 {
		t.Fatal("wrote an invalid member")
	}
}

func TestDiskStagingRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := scratch.WithDir(t.Context(), t.TempDir())
	s, err := newDiskStaging(ctx)
	if err != nil {
		t.Fatal(err)
	}
	test.CloseOnCleanup(t, s)
	w, err := s.Create("a/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := s.require("a/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
	dst, err := newDiskStaging(ctx)
	if err != nil {
		t.Fatal(err)
	}
	test.CloseOnCleanup(t, dst)
	n, err := dst.ingest(ctx, s, "a/b.txt", "c/d.txt")
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("n=%d", n)
	}
	got, err = dst.require("c/d.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("ingest got %q", got)
	}
	if err := s.putFile("e.txt", []byte("x")); err != nil {
		t.Fatal(err)
	}
	r, size, err := s.openRead("e.txt")
	if err != nil {
		t.Fatal(err)
	}
	test.CloseOnCleanup(t, r)
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if size != 1 || !bytes.Equal(b, []byte("x")) {
		t.Fatalf("openRead n=%d b=%q", size, b)
	}
}

func TestDestStageDirIsTmp(t *testing.T) {
	t.Parallel()
	d, err := OpenDirDest(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	test.CloseOnCleanup(t, d)
	dir, err := destStageDir(d)
	if err != nil {
		t.Fatal(err)
	}
	ctx := scratch.WithDir(t.Context(), dir)
	s, err := scratch.MkdirTemp(ctx, "garotafitness-stage-*")
	if err != nil {
		t.Fatal(err)
	}
	test.CloseOnCleanup(t, s)
	if s.Rel().Parent().String() != "tmp" {
		t.Fatalf("staged %s not under tmp", s.Rel())
	}
	ok, err := s.Rel().IsDir(d)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("%s missing", s.Rel())
	}
}

func TestStagingCtxRebindsWithDir(t *testing.T) {
	t.Parallel()
	d, err := OpenDirDest(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	test.CloseOnCleanup(t, d)
	dir, err := destStageDir(d)
	if err != nil {
		t.Fatal(err)
	}
	p := &reconstructionPlan{scratchDir: dir}
	s, err := newDiskStaging(p.stagingCtx(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	test.CloseOnCleanup(t, s)
	if s.stage.Rel().Parent().String() != "tmp" {
		t.Fatalf("staged %s not under tmp", s.stage.Rel())
	}
}
