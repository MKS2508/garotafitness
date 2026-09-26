package main

import (
	"bytes"
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
	require.Contains(t, got, "volumes")
	require.Contains(t, got, "registered")
	require.Contains(t, got, "tools")
	require.Contains(t, got, "SIZE")
	require.Contains(t, got, "3.0 GiB")
	require.NotContains(t, got, "recipes")
	require.NotContains(t, got, "programs")
}

func TestPrintRecipes(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printRecipes(&buf, garotafitness.RecipeReport{})
	got := buf.String()
	require.Contains(t, got, "recipes")
	require.Contains(t, got, "(none)")
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
	got = buf.String()
	require.Contains(t, got, "mover/mover.bat")
	require.Contains(t, got, "2×")
	require.Contains(t, got, "all prior")

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
	require.Contains(t, got, "10×")
	require.Contains(t, got, "(20 other groups)")
	require.Contains(t, got, "all prior")
	require.NotContains(t, got, "move unique")
}
