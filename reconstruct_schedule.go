package garotafitness

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/taskgroup"
	"github.com/lucasew/garotafitness/setupdata"
)

func (p *reconstructionPlan) resetStamps() {
	p.lastWrite = map[string]taskgroup.ID{}
	p.lastUse = map[string]taskgroup.ID{}
	p.prior = nil
	p.unknown = nil
}

func (p *reconstructionPlan) scheduleHash(ctx context.Context, path string, deps []taskgroup.ID) {
	if p.want == nil {
		return
	}
	sum := p.want[path]
	if sum == nil || p.hashed[path] || p.laterMayWrite(path) {
		return
	}
	p.hashed[path] = true
	want := append([]byte(nil), sum...)
	taskgroup.Go(ctx, "md5 "+path, taskgroup.CPU, func(ctx context.Context, s *taskgroup.Status) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		store, rel, err := p.store(lewpath.New("app", path).String())
		if err != nil {
			return err
		}
		r, n, err := store.openRead(rel)
		if err != nil {
			return err
		}
		defer r.Close()
		got, err := hashReader(ctx, r, n, s)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("installed checksum: %s: %x want %x", path, got, want)
		}
		slog.Info("verified", "path", path)
		return nil
	}, deps...)
}

func (p *reconstructionPlan) laterMayWrite(path string) bool {
	if p.opi+1 >= len(p.ops) {
		return false
	}
	return opsMayWrite(p.ops[p.opi+1:], path)
}

func opsMayWrite(ops []setupdata.Operation, path string) bool {
	for _, op := range ops {
		if op.Kind != "command" {
			continue
		}
		prog := strings.ToLower(lewpath.New(strings.ReplaceAll(op.Program, "\\", "/")).Name())
		if prog == "{cmd}" || prog == "cmd.exe" || prog == "run.exe" || prog == "x3.exe" ||
			strings.HasSuffix(prog, ".bat") || strings.HasSuffix(prog, ".cmd") ||
			prog == "x.exe" || prog == "xdelta.exe" || prog == "xdelta3.exe" ||
			prog == "x5n.exe" || prog == "x4.exe" || prog == "7z.exe" {
			return true
		}
		words, err := recipeWords(op.Args)
		if err != nil {
			return true
		}
		cwd, err := virtualPath(op.WorkDir, "")
		if err != nil {
			return true
		}
		_, writes, glob, err := recipeFiles(prog, append([]string{prog}, words...), cwd)
		if err != nil || glob {
			return true
		}
		for _, w := range writes {
			if w == path || strings.TrimPrefix(w, "app/") == path {
				return true
			}
		}
	}
	return false
}

func (p *reconstructionPlan) runScheduled(ctx context.Context, name string, fn func(context.Context) error) error {
	return withSession(ctx, func(ctx context.Context) error {
		return taskgroup.GoIsolated(ctx, name, taskgroup.Control, func(ctx context.Context, _ *taskgroup.Status) error {
			return fn(ctx)
		})
	})
}

func (p *reconstructionPlan) finishHashes(ctx context.Context) error {
	if err := p.runScheduled(ctx, "verify", func(ctx context.Context) error {
		for path := range p.want {
			p.scheduleHash(ctx, path, nil)
		}
		return nil
	}); err != nil {
		return err
	}
	for path := range p.want {
		if !p.hashed[path] {
			return fmt.Errorf("installed checksum: missing %s", path)
		}
	}
	slog.Info("installed hashes verified", "files", len(p.want))
	return nil
}

func (p *reconstructionPlan) scheduleWords(ctx context.Context, w []string, cwd string, depth int) error {
	if len(w) == 0 {
		return nil
	}
	if depth > 32 {
		return fmt.Errorf("recursive reconstruction recipe")
	}
	name := strings.ToLower(lewpath.New(strings.ReplaceAll(w[0], "\\", "/")).Name())
	a := w[1:]
	switch name {
	case "echo", "rem", "flushfilecache.exe":
		return nil
	case "call":
		if len(a) == 0 {
			return fmt.Errorf("missing called recipe")
		}
		return p.scheduleWords(ctx, a, cwd, depth+1)
	}
	if name == "run.exe" || strings.HasSuffix(name, ".bat") || strings.HasSuffix(name, ".cmd") {
		path := w[0]
		if name == "run.exe" {
			if len(a) != 4 {
				return fmt.Errorf("unsupported command-list parameters")
			}
			path = a[2]
		} else if len(a) != 0 {
			return fmt.Errorf("parameterized batch recipes are unsupported")
		}
		resolved, err := virtualPath(path, cwd)
		if err != nil {
			return err
		}
		if b, err := p.read(resolved); err == nil {
			return p.recipeLines(ctx, string(b), cwd, depth+1)
		}
		return p.scheduleLeaf(ctx, name, w, cwd, depth, []string{resolved}, nil, true, taskgroup.Control)
	}
	reads, writes, glob, err := recipeFiles(name, w, cwd)
	if err != nil {
		return err
	}
	return p.scheduleLeaf(ctx, name, w, cwd, depth, reads, writes, glob, taskgroup.CPU)
}

func leafLabel(prog string, reads, writes []string) string {
	focus := writes
	if len(focus) == 0 {
		focus = reads
	}
	if len(focus) == 0 {
		return prog
	}
	return prog + " " + strings.Join(focus, " ")
}

func (p *reconstructionPlan) scheduleLeaf(ctx context.Context, name string, w []string, cwd string, depth int, reads, writes []string, glob bool, pool taskgroup.PoolKind) error {
	deps := p.fileDeps(reads, writes, glob)
	label := leafLabel(name, reads, writes)
	id := taskgroup.Go(ctx, label, pool, func(ctx context.Context, s *taskgroup.Status) error {
		defer s.Unit()()
		var err error
		if pool == taskgroup.Control {
			err = p.expandRecipe(ctx, w, cwd, depth)
		} else {
			err = p.words(ctx, w, cwd, depth)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		return nil
	}, deps...)
	p.recordLeaf(id, reads, writes, glob)
	return nil
}

func (p *reconstructionPlan) expandRecipe(ctx context.Context, w []string, cwd string, depth int) error {
	name := strings.ToLower(lewpath.New(strings.ReplaceAll(w[0], "\\", "/")).Name())
	path := w[0]
	if name == "run.exe" {
		path = w[3]
	}
	resolved, err := virtualPath(path, cwd)
	if err != nil {
		return err
	}
	b, err := p.read(resolved)
	if err != nil {
		return err
	}
	return p.recipeLines(ctx, string(b), cwd, depth+1)
}

func (p *reconstructionPlan) fileDeps(reads, writes []string, glob bool) []taskgroup.ID {
	if glob {
		return append(append([]taskgroup.ID{}, p.prior...), p.unknown...)
	}
	seen := map[taskgroup.ID]bool{}
	var deps []taskgroup.ID
	add := func(id taskgroup.ID) {
		if id != 0 && !seen[id] {
			seen[id] = true
			deps = append(deps, id)
		}
	}
	for _, path := range reads {
		add(p.lastWrite[path])
	}
	for _, path := range writes {
		add(p.lastWrite[path])
		add(p.lastUse[path])
	}
	for _, id := range p.unknown {
		add(id)
	}
	return deps
}

func (p *reconstructionPlan) recordLeaf(id taskgroup.ID, reads, writes []string, glob bool) {
	if p.lastWrite == nil {
		p.lastWrite = map[string]taskgroup.ID{}
		p.lastUse = map[string]taskgroup.ID{}
	}
	p.prior = append(p.prior, id)
	if glob {
		p.unknown = append(p.unknown, id)
		return
	}
	for _, path := range reads {
		p.lastUse[path] = id
	}
	for _, path := range writes {
		p.lastWrite[path] = id
		delete(p.lastUse, path)
	}
}

func recipeFiles(name string, w []string, cwd string) (reads, writes []string, glob bool, err error) {
	resolve := func(s string) (string, error) { return virtualPath(s, cwd) }
	add := func(s string, write bool) error {
		if strings.ContainsAny(s, "*?[") {
			glob = true
		}
		n, e := resolve(s)
		if e != nil {
			return e
		}
		if write {
			writes = append(writes, n)
		} else {
			reads = append(reads, n)
		}
		return nil
	}
	a := w[1:]
	stripFlags := func(args []string) []string {
		out := []string{}
		for _, s := range args {
			if !strings.HasPrefix(s, "/") {
				out = append(out, s)
			}
		}
		return out
	}
	switch name {
	case "del", "erase", "rd", "rmdir":
		if name == "rd" || name == "rmdir" {
			glob = true
		}
		for _, pattern := range stripFlags(a) {
			if err = add(pattern, true); err != nil {
				return
			}
		}
	case "move", "ren", "rename":
		a = stripFlags(a)
		if len(a) != 2 {
			return
		}
		if err = add(a[0], false); err != nil {
			return
		}
		if err = add(a[0], true); err != nil {
			return
		}
		if err = add(a[1], true); err != nil {
			return
		}
	case "copy":
		a = stripFlags(a)
		if len(a) < 1 || len(a) > 2 {
			return
		}
		parts := strings.Split(a[0], "+")
		dest := parts[0]
		if len(a) == 2 {
			dest = a[1]
		}
		for _, pattern := range parts {
			if err = add(pattern, false); err != nil {
				return
			}
		}
		err = add(dest, true)
	case "fart.exe":
		if len(a) == 4 {
			err = add(a[1], true)
			reads = append(reads, writes...)
		}
	case "fsb.exe":
		if len(a) == 2 {
			if err = add(a[0], false); err != nil {
				return
			}
			err = add(a[1], true)
		}
	case "x2.exe":
		if len(a) == 2 {
			if err = add(a[0], false); err != nil {
				return
			}
			if err = add(a[1], false); err != nil {
				return
			}
			err = add(a[0], true)
		}
	case "7z.exe", "x4.exe", "x5n.exe":
		glob = true
	case "x5.exe", "hpatchz.exe":
		if len(a) > 0 && strings.HasPrefix(a[0], "-s-") {
			a = a[1:]
		}
		if len(a) == 3 {
			if err = add(a[0], false); err != nil {
				return
			}
			if err = add(a[1], false); err != nil {
				return
			}
			err = add(a[2], true)
		}
	case "fgpack.exe":
		_, source, dest, e := packingOptions(a)
		if e != nil {
			return
		}
		if err = add(source, false); err != nil {
			return
		}
		err = add(dest, true)
	case "x.exe", "xdelta.exe", "xdelta3.exe":
		glob = true
	case "x3.exe":
		if len(a) == 1 {
			if err = add(a[0], false); err != nil {
				return
			}
		}
		glob = true
	default:
		if strings.HasSuffix(name, ".bat") || strings.HasSuffix(name, ".cmd") {
			err = add(w[0], false)
			glob = true
		}
	}
	return
}
