package garotafitness

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/stretchr/testify/require"
)

func TestInspectEmptySource(t *testing.T) {
	t.Parallel()
	r, err := Inspect(t.Context(), fstest.MapFS{})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, c := range r.Codecs {
		ids[c.ID] = true
	}
	if !ids["lzma"] || !ids["i3d"] || !ids["xdelta"] {
		t.Fatalf("codecs %v", r.Codecs)
	}
	if len(r.Tools) != 0 {
		t.Fatalf("tools=%v", r.Tools)
	}
}

func TestToolsetDescribe(t *testing.T) {
	t.Parallel()
	if g := reconstructToolset.describe("fgpack.exe", ""); g != "lzma (name)" {
		t.Fatalf("%q", g)
	}
	if g := reconstructToolset.describe("fgpack.exe", "a95222984f60e3f5bea4099cab85868946523391b0e50d7f6dcc5e866d0b0dbd"); g != "lzma (hash)" {
		t.Fatalf("%q", g)
	}
	if g := reconstructToolset.describe("fgpack.exe", "eb9a914ff781bc2f088e70d1b99faca73d98a96325a4a154cf52b3b52a4f860a"); g != "i3d (hash)" {
		t.Fatalf("%q", g)
	}
	if g := reconstructToolset.describe("x.exe", ""); g != "xdelta (name)" {
		t.Fatalf("%q", g)
	}
	if g := reconstructToolset.describe("xdelta3.exe", "09763ca90c09a5f815a94527399b1f2a88685e9de462e2ff1bc5648d320e707a"); g != "xdelta (hash)" {
		t.Fatalf("%q", g)
	}
	if g := reconstructToolset.describe("x4.exe", "7889aadec74fe2e4940a3dab081b8d560d7d751b0ed13cfc90b8986ca6ae084f"); g != "defarm (hash)" {
		t.Fatalf("%q", g)
	}
	s := &toolset{byHash: map[string]codec{}, byName: map[string][]codec{}}
	s.add(codec{id: "lzma", sha256: "aaa", names: []string{"codec-test.exe"}})
	s.add(codec{id: "other", sha256: "bbb", names: []string{"codec-test.exe"}})
	if g := s.describe("codec-test.exe", "bbb"); g != "other (hash)" {
		t.Fatalf("%q", g)
	}
	if g := s.describe("codec-test.exe", "ccc"); g != "checksum" {
		t.Fatalf("%q", g)
	}
}

func TestInspectFS25(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	r, err := Inspect(t.Context(), src)
	require.NoError(t, err)
	require.NotEmpty(t, r.Volumes)
	require.NotEmpty(t, r.Tools)
	for _, v := range r.Volumes {
		t.Logf("volume %s size=%d files=%d pipe=%s", v.Name, v.Size, v.Files, v.Pipeline)
		require.Greater(t, v.Size, int64(0), v.Name)
	}
	for _, c := range r.Codecs {
		t.Logf("codec name=%s id=%s sha256=%s", c.Name, c.ID, c.SHA256)
	}
	var sawFgpack, sawX4 bool
	for _, tool := range r.Tools {
		t.Logf("tool name=%s size=%d sha256=%s match=%s", tool.Name, tool.Size, tool.SHA256, tool.Match)
		if tool.Name == "fgpack.exe" {
			sawFgpack = true
			require.Equal(t, "i3d (hash)", tool.Match)
		}
		if tool.Name == "x.exe" {
			require.Equal(t, "xdelta (hash)", tool.Match)
		}
		if tool.Name == "x4.exe" {
			sawX4 = true
			require.Equal(t, "defarm (hash)", tool.Match)
		}
	}
	require.True(t, sawFgpack, "fgpack.exe missing from installer tools")
	require.True(t, sawX4, "x4.exe missing from installer tools")
}

func TestInspectRimWorld(t *testing.T) {
	src := corpus.OpenEnv(t, "GAROTAFITNESS_CORPUS")
	r, err := Inspect(t.Context(), src)
	require.NoError(t, err)
	var sawFgpack, sawX bool
	for _, tool := range r.Tools {
		if tool.Name == "fgpack.exe" {
			sawFgpack = true
			require.Equal(t, "lzma (hash)", tool.Match)
		}
		if tool.Name == "x.exe" {
			sawX = true
			require.Equal(t, "xdelta (hash)", tool.Match)
		}
	}
	require.True(t, sawFgpack, "fgpack.exe missing from installer tools")
	require.True(t, sawX, "x.exe missing from installer tools")
}

func TestRecipesEmptySource(t *testing.T) {
	t.Parallel()
	r, err := Recipes(t.Context(), fstest.MapFS{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Recipes) != 0 {
		t.Fatalf("%v", r.Recipes)
	}
}

func TestRecipesFS25(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	r, err := Recipes(t.Context(), src)
	require.NoError(t, err)
	require.NotEmpty(t, r.Recipes)
	var mover *Recipe
	for i := range r.Recipes {
		rec := &r.Recipes[i]
		t.Logf("recipe %s lines=%d groups=%d", rec.Path, rec.Lines, len(rec.Groups))
		if strings.HasSuffix(rec.Path, "mover.bat") {
			mover = rec
		}
	}
	require.NotNil(t, mover)
	require.Greater(t, mover.Lines, 1000)
	last := mover.Groups[len(mover.Groups)-1]
	require.Equal(t, "all prior", last.Wait)
}

func TestInspectRecipeGraph(t *testing.T) {
	t.Parallel()
	steps, err := inspectRecipeGraph("fgpack.exe e -d24 -fb32 a.bin b.bin\ndel a.bin\n", "tmp")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 {
		t.Fatalf("steps %d", len(steps))
	}
	if len(steps[0].writes) == 0 || len(steps[1].wait) == 0 {
		t.Fatalf("%+v", steps)
	}
	g := groupRecipeSteps(steps)
	if len(g) != 2 {
		t.Fatalf("groups %d", len(g))
	}
}

func TestGroupRecipeSteps(t *testing.T) {
	t.Parallel()
	g := groupRecipeSteps([]recipeStep{
		{n: 1, line: `move temp\0001.shapes dataS\0001.shapes`},
		{n: 2, line: `move temp\0002.shapes dataS\0002.shapes`},
		{n: 3, line: "rd temp", glob: true},
	})
	if len(g) != 2 {
		t.Fatalf("groups %d: %+v", len(g), g)
	}
	if g[0].Count != 2 || g[0].Wait != "—" || !strings.Contains(g[0].Pattern, "N.shapes") {
		t.Fatalf("moves %+v", g[0])
	}
	if g[1].Count != 1 || g[1].Wait != "all prior" || g[1].Pattern != "rd temp" {
		t.Fatalf("rd %+v", g[1])
	}
}
