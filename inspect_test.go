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
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, c := range r.Codecs {
		ids[c.ID] = true
	}
	require.Contains(t, ids, "lzma", "codecs %v", r.Codecs)
	require.Contains(t, ids, "i3d", "codecs %v", r.Codecs)
	require.Contains(t, ids, "xdelta", "codecs %v", r.Codecs)
	require.Empty(t, r.Tools)
}

func TestToolsetDescribe(t *testing.T) {
	t.Parallel()
	require.Equal(t, "lzma (name)", reconstructToolset.describe("fgpack.exe", ""))
	require.Equal(t, "lzma (hash)", reconstructToolset.describe("fgpack.exe", "a95222984f60e3f5bea4099cab85868946523391b0e50d7f6dcc5e866d0b0dbd"))
	require.Equal(t, "i3d (hash)", reconstructToolset.describe("fgpack.exe", "eb9a914ff781bc2f088e70d1b99faca73d98a96325a4a154cf52b3b52a4f860a"))
	require.Equal(t, "xdelta (name)", reconstructToolset.describe("x.exe", ""))
	require.Equal(t, "xdelta (hash)", reconstructToolset.describe("xdelta3.exe", "09763ca90c09a5f815a94527399b1f2a88685e9de462e2ff1bc5648d320e707a"))
	require.Equal(t, "defarm (hash)", reconstructToolset.describe("x4.exe", "7889aadec74fe2e4940a3dab081b8d560d7d751b0ed13cfc90b8986ca6ae084f"))
	s := &toolset{byHash: map[string]codec{}, byName: map[string][]codec{}}
	s.add(codec{id: "lzma", sha256: "aaa", names: []string{"codec-test.exe"}})
	s.add(codec{id: "other", sha256: "bbb", names: []string{"codec-test.exe"}})
	require.Equal(t, "other (hash)", s.describe("codec-test.exe", "bbb"))
	require.Equal(t, "checksum", s.describe("codec-test.exe", "ccc"))
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
	require.NoError(t, err)
	require.Empty(t, r.Recipes)
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
	require.NoError(t, err)
	require.Len(t, steps, 2)
	require.NotEmpty(t, steps[0].writes, "%+v", steps)
	require.NotEmpty(t, steps[1].wait, "%+v", steps)
	g := groupRecipeSteps(steps)
	require.Len(t, g, 2)
}

func TestGroupRecipeSteps(t *testing.T) {
	t.Parallel()
	g := groupRecipeSteps([]recipeStep{
		{n: 1, line: `move temp\0001.shapes dataS\0001.shapes`},
		{n: 2, line: `move temp\0002.shapes dataS\0002.shapes`},
		{n: 3, line: "rd temp", glob: true},
	})
	require.Len(t, g, 2)
	require.Equal(t, 2, g[0].Count)
	require.Equal(t, "—", g[0].Wait)
	require.Contains(t, g[0].Pattern, "N.shapes")
	require.Equal(t, 1, g[1].Count)
	require.Equal(t, "all prior", g[1].Wait)
	require.Equal(t, "rd temp", g[1].Pattern)
}
