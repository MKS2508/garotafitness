package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"text/tabwriter"

	"github.com/lewtec/lewkit/x/cmd"
	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/taskgroup"
	"github.com/lewtec/lewkit/x/taskgroup/progress"
	"github.com/lucasew/garotafitness"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

type root struct {
	taskgroup.Arg `flatten:"" ctx:"taskgroup"`
	Extract       *extractCmd `cmd:"extract"`
	Inspect       *inspectCmd `cmd:"inspect"`
	Recipe        *recipeCmd  `cmd:"recipe"`
}

func (root) Description() string {
	return "Extract a local FitGirl repack into a destination tree."
}

type extractCmd struct {
	Source cmd.WorkDirArg `help:"repack directory with setup.exe and fg-*.bin volumes"`
	Dest   cmd.DataDirArg `help:"destination directory"`
}

func (extractCmd) Description() string {
	return "extract SOURCE into DEST using setup.exe metadata and volume pipelines"
}

func (c *extractCmd) Run(ctx context.Context) error {
	srcPath := c.Source.Value()
	dstPath := c.Dest.Value()
	if srcPath == "" || dstPath == "" {
		return cmd.ErrUsage
	}
	sess, ctx := enterSession(ctx)
	return progress.Run(sess, ctx, func(ctx context.Context) error {
		src, err := lewpath.Open(srcPath)
		if err != nil {
			return err
		}
		defer src.Close()
		dst, err := garotafitness.OpenDirDest(dstPath)
		if err != nil {
			return err
		}
		defer dst.Close()
		slog.Info("extract", "source", src.Name(), "dest", dst.Name())
		return garotafitness.Extractor{Source: src, Dest: dst}.Extract(ctx)
	})
}

type inspectCmd struct {
	Source cmd.WorkDirArg `help:"repack directory with setup.exe and fg-*.bin volumes"`
}

func (inspectCmd) Description() string {
	return "unpack installer tools from SOURCE and show codec matches"
}

func (c *inspectCmd) Run(ctx context.Context) error {
	if c.Source.Value() == "" {
		return cmd.ErrUsage
	}
	sess, ctx := enterSession(ctx)
	var rep garotafitness.InspectReport
	err := progress.Run(sess, ctx, func(ctx context.Context) error {
		src, err := lewpath.Open(c.Source.Value())
		if err != nil {
			return err
		}
		defer src.Close()
		rep, err = garotafitness.Inspect(ctx, src)
		return err
	})
	if err != nil {
		return err
	}
	printInspect(os.Stdout, rep)
	return nil
}

type recipeCmd struct {
	Source cmd.WorkDirArg `help:"repack directory with setup.exe and fg-*.bin volumes"`
}

func (recipeCmd) Description() string {
	return "unpack installer batch files from SOURCE and show reconstruct waits"
}

func (c *recipeCmd) Run(ctx context.Context) error {
	if c.Source.Value() == "" {
		return cmd.ErrUsage
	}
	sess, ctx := enterSession(ctx)
	var rep garotafitness.RecipeReport
	err := progress.Run(sess, ctx, func(ctx context.Context) error {
		src, err := lewpath.Open(c.Source.Value())
		if err != nil {
			return err
		}
		defer src.Close()
		rep, err = garotafitness.Recipes(ctx, src)
		return err
	})
	if err != nil {
		return err
	}
	printRecipes(os.Stdout, rep)
	return nil
}

func printInspect(w io.Writer, r garotafitness.InspectReport) {
	inspectSection(w, "volumes", len(r.Volumes), func(tw *tabwriter.Writer) {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", "NAME", "SIZE", "FILES", "PIPELINE")
		for _, v := range r.Volumes {
			fmt.Fprintf(tw, "  %s\t%s\t%d\t%s\n", v.Name, inspectSize(v.Size), v.Files, v.Pipeline)
		}
	})
	inspectSection(w, "registered", len(r.Codecs), func(tw *tabwriter.Writer) {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", "EXE", "CODEC", "HASH")
		for _, c := range r.Codecs {
			sum := c.SHA256
			if sum == "" {
				sum = "*"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.Name, c.ID, sum)
		}
	})
	inspectSection(w, "tools", len(r.Tools), func(tw *tabwriter.Writer) {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", "NAME", "SIZE", "MATCH", "SHA256")
		for _, t := range r.Tools {
			sum := t.SHA256
			if len(sum) > 16 {
				sum = sum[:16]
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", t.Name, inspectSize(t.Size), t.Match, sum)
		}
	})
}

func printRecipes(w io.Writer, r garotafitness.RecipeReport) {
	fmt.Fprintln(w, "recipes")
	if len(r.Recipes) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	for _, rec := range r.Recipes {
		fmt.Fprintf(w, "  %s  (%d commands, %d groups)\n", rec.Path, rec.Lines, len(rec.Groups))
		groups := rec.Groups
		if len(groups) > 8 {
			groups = clipRecipeGroups(groups)
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "    %s\t%s\t%s\n", "N", "WAIT", "PATTERN")
		for _, g := range groups {
			fmt.Fprintf(tw, "    %d×\t%s\t%s\n", g.Count, g.Wait, g.Pattern)
		}
		tw.Flush()
	}
}

func clipRecipeGroups(g []garotafitness.RecipeGroup) []garotafitness.RecipeGroup {
	best := 0
	for i := range g {
		if g[i].Count > g[best].Count {
			best = i
		}
	}
	last := len(g) - 1
	var rest garotafitness.RecipeGroup
	n := 0
	for i, x := range g {
		if i == best || i == last {
			continue
		}
		rest.Count += x.Count
		n++
	}
	out := []garotafitness.RecipeGroup{g[best]}
	if n > 0 {
		rest.Pattern = fmt.Sprintf("(%d other groups)", n)
		out = append(out, rest)
	}
	if last != best {
		out = append(out, g[last])
	}
	return out
}

func inspectSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	default:
		return strconv.FormatInt(n, 10)
	}
}

func inspectSection(w io.Writer, title string, n int, write func(*tabwriter.Writer)) {
	fmt.Fprintln(w, title)
	if n == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	write(tw)
	tw.Flush()
}

func enterSession(ctx context.Context) (*taskgroup.Session, context.Context) {
	if s := taskgroup.FromContext(ctx); s != nil {
		return s, ctx
	}
	if arg, ok := cmd.Lookup[taskgroup.Arg](ctx, "taskgroup"); ok {
		return arg.Enter(ctx, taskgroup.DefaultLimits())
	}
	return taskgroup.New(ctx, taskgroup.DefaultLimits())
}

func run(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	context.AfterFunc(ctx, func() {
		if err := ctx.Err(); err != nil {
			slog.Warn("interrupt or parent cancel", "err", err, "cause", context.Cause(ctx))
		}
	})
	app, err := cmd.Parse[cmd.App[root]](args...)
	if err != nil {
		return err
	}
	err = app.Run(ctx)
	if err != nil {
		slog.Error(err.Error(), "cause", context.Cause(ctx))
	}
	return err
}
