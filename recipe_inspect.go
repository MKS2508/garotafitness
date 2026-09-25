package garotafitness

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	lewpath "github.com/lewtec/lewkit/x/path"
)

// RecipeReport is unpacked reconstruct batch files and grouped waits.
type RecipeReport struct {
	Recipes []Recipe
}

// Recipe is one .bat/.cmd and consecutive command groups.
type Recipe struct {
	Path   string
	Lines  int
	Groups []RecipeGroup
}

// RecipeGroup is consecutive lines that share a pattern and wait.
type RecipeGroup struct {
	Count   int
	Pattern string
	Wait    string
}

type recipeStep struct {
	n             int
	line          string
	reads, writes []string
	glob          bool
	wait          []int
}

// Recipes unpacks installer tmp volumes and reports batch file waits.
func Recipes(ctx context.Context, src fs.FS) (RecipeReport, error) {
	if src == nil {
		return RecipeReport{}, fmt.Errorf("nil source")
	}
	setup, err := readSetup(src)
	if err != nil {
		return RecipeReport{}, fmt.Errorf("setup.exe: %w", err)
	}
	vols, err := listVolumes(src)
	if err != nil {
		vols = nil
	}
	staged, err := unpackTmp(ctx, src, setup.Operations, vols)
	if err != nil || staged == nil {
		return RecipeReport{}, err
	}
	defer staged.Close()
	list, err := inspectRecipes(staged)
	return RecipeReport{Recipes: list}, err
}

func inspectRecipes(staged *reconstruction) ([]Recipe, error) {
	staged.mu.Lock()
	names := slices.Sorted(maps.Keys(staged.files))
	staged.mu.Unlock()
	var out []Recipe
	for _, name := range names {
		ext := strings.ToLower(path.Ext(name))
		if ext != ".bat" && ext != ".cmd" {
			continue
		}
		b, err := staged.require(name)
		if err != nil {
			return nil, err
		}
		cwd := lewpath.New("tmp", path.Dir(name)).String()
		steps, err := inspectRecipeGraph(string(b), cwd)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, Recipe{Path: name, Lines: len(steps), Groups: groupRecipeSteps(steps)})
	}
	return out, nil
}

var recipeDigits = regexp.MustCompile(`\d+`)

func groupRecipeSteps(steps []recipeStep) []RecipeGroup {
	var out []RecipeGroup
	for _, s := range steps {
		pat := recipeDigits.ReplaceAllString(s.line, "N")
		wait := "—"
		switch {
		case s.glob:
			wait = "all prior"
		case len(s.wait) == 1:
			wait = fmt.Sprintf("#%d", s.wait[0])
		case len(s.wait) > 1:
			wait = fmt.Sprintf("#%d+%d", s.wait[0], len(s.wait)-1)
		}
		if n := len(out); n > 0 && out[n-1].Pattern == pat && out[n-1].Wait == wait {
			out[n-1].Count++
			continue
		}
		out = append(out, RecipeGroup{Count: 1, Pattern: pat, Wait: wait})
	}
	return out
}

func inspectRecipeGraph(text, cwd string) ([]recipeStep, error) {
	cmds, err := recipeCommands(text)
	if err != nil {
		return nil, err
	}
	lastWrite := map[string]int{}
	lastUse := map[string]int{}
	var unknown []int
	var steps []recipeStep
	for _, part := range cmds {
		words, err := recipeWords(part)
		if err != nil {
			return nil, err
		}
		if len(words) == 0 {
			continue
		}
		name := strings.ToLower(lewpath.New(strings.ReplaceAll(words[0], "\\", "/")).Name())
		reads, writes, glob, err := recipeFiles(name, words, cwd)
		if err != nil {
			return nil, err
		}
		n := len(steps) + 1
		var wait []int
		if !glob {
			wait = inspectFileDeps(n, reads, writes, lastWrite, lastUse, unknown)
		}
		steps = append(steps, recipeStep{n: n, line: part, reads: reads, writes: writes, glob: glob, wait: wait})
		if glob {
			unknown = append(unknown, n)
			continue
		}
		for _, pth := range reads {
			lastUse[pth] = n
		}
		for _, pth := range writes {
			lastWrite[pth] = n
			delete(lastUse, pth)
		}
	}
	return steps, nil
}

func inspectFileDeps(n int, reads, writes []string, lastWrite, lastUse map[string]int, unknown []int) []int {
	var wait []int
	add := func(id int) {
		if id != 0 && id != n {
			wait = append(wait, id)
		}
	}
	for _, pth := range reads {
		add(lastWrite[pth])
	}
	for _, pth := range writes {
		add(lastWrite[pth])
		add(lastUse[pth])
	}
	for _, id := range unknown {
		add(id)
	}
	return uniqueInts(wait)
}

func uniqueInts(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, n := range in {
		if n == 0 || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
