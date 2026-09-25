package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lewtec/lewkit/x/cmd"
	"github.com/lucasew/garotafitness"
	"github.com/stretchr/testify/require"
)

func TestParseExtract(t *testing.T) {
	t.Parallel()
	_, err := cmd.Parse[cmd.App[root]]()
	require.NoError(t, err)

	app, err := cmd.Parse[cmd.App[root]]("extract")
	require.NoError(t, err)
	require.NotNil(t, app.Args.Extract)
	require.Error(t, app.Args.Extract.Run(t.Context()))

	src := t.TempDir()
	dst := t.TempDir()
	app, err = cmd.Parse[cmd.App[root]]("extract", src, dst)
	require.NoError(t, err)
	require.NotNil(t, app.Args.Extract)
	require.Equal(t, src, app.Args.Extract.Source.Value())
	require.Equal(t, dst, app.Args.Extract.Dest.Value())

	app, err = cmd.Parse[cmd.App[root]]("--cpu", "2", "extract", src, dst)
	require.NoError(t, err)
	require.Equal(t, 2, app.Args.CPU.Value())

	_, err = cmd.Parse[cmd.App[root]]("--pprof", ":6060", "extract", src, dst)
	require.NoError(t, err)
}

func TestParseInspect(t *testing.T) {
	t.Parallel()
	app, err := cmd.Parse[cmd.App[root]]("inspect")
	require.NoError(t, err)
	require.NotNil(t, app.Args.Inspect)

	src := t.TempDir()
	app, err = cmd.Parse[cmd.App[root]]("inspect", src)
	require.NoError(t, err)
	require.Equal(t, src, app.Args.Inspect.Source.Value())
}

func TestParseRecipe(t *testing.T) {
	t.Parallel()
	app, err := cmd.Parse[cmd.App[root]]("recipe")
	require.NoError(t, err)
	require.NotNil(t, app.Args.Recipe)

	src := t.TempDir()
	app, err = cmd.Parse[cmd.App[root]]("recipe", src)
	require.NoError(t, err)
	require.Equal(t, src, app.Args.Recipe.Source.Value())
}

func TestPrintInspectDropsRecipes(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printInspect(&buf, garotafitness.InspectReport{
		Volumes: []garotafitness.InspectVolume{{Name: "fg-01.bin", Size: 3 << 30, Files: 2, Pipeline: "rzs"}},
	})
	got := buf.String()
	if !strings.Contains(got, "volumes") || !strings.Contains(got, "registered") || !strings.Contains(got, "tools") {
		t.Fatalf("%q", got)
	}
	if !strings.Contains(got, "SIZE") || !strings.Contains(got, "3.0 GiB") {
		t.Fatalf("missing volume size: %q", got)
	}
	if strings.Contains(got, "recipes") || strings.Contains(got, "programs") {
		t.Fatalf("leftover sections: %q", got)
	}
}

func TestPrintRecipes(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printRecipes(&buf, garotafitness.RecipeReport{})
	if got := buf.String(); !strings.Contains(got, "recipes") || !strings.Contains(got, "(none)") {
		t.Fatalf("%q", got)
	}
	buf.Reset()
	printRecipes(&buf, garotafitness.RecipeReport{
		Recipes: []garotafitness.Recipe{{
			Path:  "mover/mover.bat",
			Lines: 3,
			Groups: []garotafitness.RecipeGroup{
				{Count: 2, Wait: "—", Pattern: `move temp\N.shapes dataS\N.shapes`},
				{Count: 1, Wait: "all prior", Pattern: "rd temp"},
			},
		}},
	})
	got := buf.String()
	if !strings.Contains(got, "mover/mover.bat") || !strings.Contains(got, "2×") || !strings.Contains(got, "all prior") {
		t.Fatalf("%q", got)
	}

	buf.Reset()
	var many []garotafitness.RecipeGroup
	many = append(many, garotafitness.RecipeGroup{Count: 10, Wait: "—", Pattern: "move A"})
	for range 20 {
		many = append(many, garotafitness.RecipeGroup{Count: 1, Wait: "—", Pattern: "move unique"})
	}
	many = append(many, garotafitness.RecipeGroup{Count: 1, Wait: "all prior", Pattern: "rd temp"})
	printRecipes(&buf, garotafitness.RecipeReport{
		Recipes: []garotafitness.Recipe{{Path: "big.bat", Lines: 31, Groups: many}},
	})
	got = buf.String()
	if !strings.Contains(got, "10×") || !strings.Contains(got, "(20 other groups)") || !strings.Contains(got, "all prior") {
		t.Fatalf("%q", got)
	}
	if strings.Contains(got, "move unique") {
		t.Fatalf("did not collapse unique rows: %q", got)
	}
}
