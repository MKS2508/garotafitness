package garotafitness

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/taskgroup"
	"github.com/lucasew/garotafitness/reconstruct/fgpack"
	"github.com/lucasew/garotafitness/reconstruct/fsb"
	"github.com/lucasew/garotafitness/reconstruct/sevenz"
	"github.com/lucasew/garotafitness/reconstruct/x2"
	"github.com/lucasew/garotafitness/reconstruct/x3"
	"github.com/lucasew/garotafitness/reconstruct/x4"
	"github.com/lucasew/garotafitness/reconstruct/x5"
	"github.com/lucasew/garotafitness/reconstruct/x5n"
	"github.com/lucasew/garotafitness/reconstruct/xdelta"
)

// Recipe commands are parsed into a fixed set of file transformations. Nothing
// is passed to a shell, and executable files named by a recipe are never loaded.
func recipeWords(line string) ([]string, error) {
	var out []string
	var word strings.Builder
	quoted, started := false, false
	for _, c := range line {
		switch {
		case c == '"':
			quoted = !quoted
			started = true
		case (c == ' ' || c == '\t') && !quoted:
			if started {
				out = append(out, word.String())
				word.Reset()
				started = false
			}
		case !quoted && strings.ContainsRune("|<>^&", c):
			return nil, fmt.Errorf("unsupported recipe operator %q", c)
		default:
			word.WriteRune(c)
			started = true
		}
	}
	if quoted {
		return nil, fmt.Errorf("unterminated recipe quote")
	}
	if started {
		out = append(out, word.String())
	}
	return out, nil
}

func (p *reconstructionPlan) recipe(ctx context.Context, text, cwd string, depth int) error {
	p.resetStamps()
	return withSession(ctx, func(ctx context.Context) error {
		if err := p.recipeLines(ctx, text, cwd, depth); err != nil {
			return err
		}
		if err := p.waitScheduled(); err != nil {
			return err
		}
		for path := range p.lastWrite {
			p.scheduleHash(ctx, path, nil)
		}
		return nil
	})
}

func (p *reconstructionPlan) recipeLines(ctx context.Context, text, cwd string, depth int) error {
	if depth > 32 {
		return fmt.Errorf("recursive reconstruction recipe")
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "@")
		if line == "" || strings.HasPrefix(line, "::") || strings.HasPrefix(strings.ToLower(line), "rem ") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "cmd /c ") {
			line = strings.TrimSpace(line[7:])
		}
		if strings.HasPrefix(line, "\"\"") && strings.HasSuffix(line, "\"") {
			line = line[1 : len(line)-1]
		}
		if strings.HasPrefix(line, "\"") && strings.HasSuffix(line, "\"") && strings.Count(line, "\"") == 2 {
			line = line[1 : len(line)-1]
		}
		start := 0
		quoted := false
		for i := 0; i <= len(line); i++ {
			if i < len(line) && line[i] == '"' {
				quoted = !quoted
			}
			if i != len(line) && (quoted || line[i] != '&') {
				continue
			}
			if i < len(line) && (i+1 >= len(line) || line[i+1] != '&') {
				return fmt.Errorf("unsupported recipe command separator")
			}
			part := strings.TrimSpace(line[start:i])
			words, err := recipeWords(part)
			if err != nil {
				return err
			}
			if len(words) > 0 {
				if err := p.scheduleWords(ctx, words, cwd, depth+1); err != nil {
					return fmt.Errorf("recipe %q: %w", part, err)
				}
			}
			if i < len(line) {
				i++
				start = i + 1
			}
		}
		if quoted {
			return fmt.Errorf("unterminated recipe quote")
		}
	}
	return nil
}

func (p *reconstructionPlan) command(ctx context.Context, program, args, cwd string, depth int) error {
	p.resetStamps()
	if strings.EqualFold(program, "{cmd}") || strings.EqualFold(lewpath.New(strings.ReplaceAll(program, "\\", "/")).Name(), "cmd.exe") {
		if len(args) < 3 || !strings.EqualFold(args[:3], "/c ") {
			return fmt.Errorf("unsupported cmd parameters %q", args)
		}
		return p.recipe(ctx, strings.TrimSpace(args[3:]), cwd, depth+1)
	}
	words, err := recipeWords(args)
	if err != nil {
		return err
	}
	return withSession(ctx, func(ctx context.Context) error {
		if err := p.scheduleWords(ctx, append([]string{program}, words...), cwd, depth+1); err != nil {
			return err
		}
		if err := p.waitScheduled(); err != nil {
			return err
		}
		for path := range p.lastWrite {
			p.scheduleHash(ctx, path, nil)
		}
		return nil
	})
}

func (p *reconstructionPlan) words(ctx context.Context, w []string, cwd string, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > 32 {
		return fmt.Errorf("recursive reconstruction recipe")
	}
	name := strings.ToLower(lewpath.New(strings.ReplaceAll(w[0], "\\", "/")).Name())
	a := w[1:]
	slog.Info("recipe command", "program", name, "args", a, "cwd", cwd)
	resolve := func(s string) (string, error) { return virtualPath(s, cwd) }
	read := func(s string) ([]byte, error) {
		n, e := resolve(s)
		if e != nil {
			return nil, e
		}
		return p.read(n)
	}
	put := func(s string, b []byte) error {
		n, e := resolve(s)
		if e != nil {
			return e
		}
		return p.put(n, b)
	}
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
	case "echo", "rem", "flushfilecache.exe":
		return nil // output and host-cache hints
	case "call":
		if len(a) == 0 {
			return fmt.Errorf("missing called recipe")
		}
		return p.words(ctx, a, cwd, depth+1)
	case "del", "erase", "rd", "rmdir":
		for _, pattern := range stripFlags(a) {
			n, err := resolve(pattern)
			if err != nil {
				return err
			}
			if name == "rd" || name == "rmdir" {
				if err := p.remove(n, true); err != nil {
					return err
				}
				slog.Info("removed tree", "path", n)
				continue
			}
			matches, err := p.matches(n, false)
			if err != nil {
				return err
			}
			for _, m := range matches {
				if err := p.remove(m, false); err != nil {
					return err
				}
				slog.Info("deleted", "path", m)
			}
		}
		return nil
	case "move", "ren", "rename":
		a = stripFlags(a)
		if len(a) != 2 {
			return fmt.Errorf("invalid move arguments")
		}
		source, err := resolve(a[0])
		if err != nil {
			return err
		}
		dest, err := resolve(a[1])
		if err != nil {
			return err
		}
		if name == "ren" || name == "rename" {
			dest, err = virtualPath(a[1], lewpath.New(source).Parent().String())
			if err != nil {
				return err
			}
		}
		b, err := p.read(source)
		if err != nil {
			return err
		}
		if strings.HasSuffix(a[1], "\\") || strings.HasSuffix(a[1], "/") {
			dest = lewpath.New(dest, lewpath.New(source).Name()).String()
		}
		if err := p.remove(source, false); err != nil {
			return err
		}
		if err := p.put(dest, b); err != nil {
			return err
		}
		slog.Info("moved", "from", source, "to", dest, "size", len(b))
		return nil
	case "copy":
		a = stripFlags(a)
		if len(a) < 1 || len(a) > 2 {
			return fmt.Errorf("unsupported copy arguments")
		}
		parts := strings.Split(a[0], "+")
		dest := parts[0]
		if len(a) == 2 {
			dest = a[1]
		}
		var out []byte
		for _, pattern := range parts {
			n, err := resolve(pattern)
			if err != nil {
				return err
			}
			matches, err := p.matches(n, false)
			if err != nil {
				return err
			}
			if len(matches) == 0 && !strings.ContainsAny(pattern, "*?[") {
				return fmt.Errorf("missing copy source %s", pattern)
			}
			for _, m := range matches {
				b, err := p.read(m)
				if err != nil {
					return err
				}
				out = append(out, b...)
			}
		}
		return put(dest, out)
	case "fart.exe":
		if len(a) != 4 || a[0] != "-w" {
			return fmt.Errorf("unsupported recipe replacement parameters")
		}
		pattern, err := resolve(a[1])
		if err != nil {
			return err
		}
		matches, err := p.matches(pattern, false)
		if err != nil {
			return err
		}
		for _, n := range matches {
			b, err := p.read(n)
			if err != nil {
				return err
			}
			if err := p.put(n, bytes.ReplaceAll(b, []byte(a[2]), []byte(a[3]))); err != nil {
				return err
			}
		}
		return nil
	case "run.exe":
		if len(a) != 4 {
			return fmt.Errorf("unsupported command-list parameters")
		}
		b, err := read(a[2])
		if err != nil {
			return err
		}
		return p.recipe(ctx, string(b), cwd, depth+1)
	case "fsb.exe":
		if len(a) != 2 {
			return fmt.Errorf("invalid FSB remux parameters")
		}
		b, err := read(a[0])
		if err != nil {
			return err
		}
		var out bytes.Buffer
		if err := fsb.Remux(ctx, &out, bytes.NewReader(b)); err != nil {
			return err
		}
		slog.Info("fsb", "src", a[0], "dst", a[1], "in", len(b), "out", out.Len())
		return put(a[1], out.Bytes())
	case "x2.exe":
		if len(a) != 2 {
			return fmt.Errorf("invalid x2 parameters")
		}
		old, err := read(a[0])
		if err != nil {
			return err
		}
		diff, err := read(a[1])
		if err != nil {
			return err
		}
		out, err := x2.Apply(old, diff)
		if err != nil {
			return err
		}
		dst, err := resolve(a[0])
		if err != nil {
			return err
		}
		slog.Info("x2", "file", dst, "patch", a[1], "in", len(old), "out", len(out))
		return put(a[0], out)
	case "x5.exe", "hpatchz.exe":
		if len(a) > 0 && strings.HasPrefix(a[0], "-s-") {
			a = a[1:]
		}
		if len(a) != 3 {
			return fmt.Errorf("unsupported HDiffPatch parameters")
		}
		old, err := read(a[0])
		if err != nil {
			return err
		}
		diff, err := read(a[1])
		if err != nil {
			return err
		}
		out, err := x5.Apply(ctx, old, diff)
		if err != nil {
			return err
		}
		dst, err := resolve(a[2])
		if err != nil {
			return err
		}
		slog.Info("x5", "old", a[0], "diff", a[1], "dst", dst, "in", len(old), "out", len(out))
		return put(a[2], out)
	case "7z.exe":
		archive, sources, err := sevenzArgs(a)
		if err != nil {
			return err
		}
		var files []sevenz.File
		for _, pattern := range sources {
			n, err := resolve(pattern)
			if err != nil {
				return err
			}
			matches, err := p.matches(n, false)
			if err != nil {
				return err
			}
			if len(matches) == 0 && !strings.ContainsAny(pattern, "*?[") {
				return fmt.Errorf("missing 7z source %s", pattern)
			}
			for _, m := range matches {
				b, err := p.read(m)
				if err != nil {
					return err
				}
				name := m
				if rel, ok := strings.CutPrefix(m, cwd+"/"); ok {
					name = rel
				} else {
					name = lewpath.New(m).Name()
				}
				files = append(files, sevenz.File{Name: name, Data: b})
			}
		}
		out, err := sevenz.Encode(ctx, files)
		if err != nil {
			return err
		}
		dst, err := resolve(archive)
		if err != nil {
			return err
		}
		slog.Info("7z", "dst", dst, "files", len(files), "out", len(out))
		return put(archive, out)
	case "x5n.exe":
		return p.x5n(ctx, a, cwd)
	case "x4.exe":
		return p.x4(a, cwd)
	case "fgpack.exe":
		options, source, dest, err := packingOptions(a)
		if err != nil {
			return err
		}
		b, err := read(source)
		if err != nil {
			return err
		}
		src, err := resolve(source)
		if err != nil {
			return err
		}
		dst, err := resolve(dest)
		if err != nil {
			return err
		}
		out, err := fgpack.EncodeWithOptions(ctx, b, options)
		if err != nil {
			return err
		}
		slog.Info("fgpack", "src", src, "dst", dst, "in", len(b), "out", len(out))
		return put(dest, out)
	case "x.exe", "xdelta.exe", "xdelta3.exe":
		var source string
		var files []string
		decode := false
		for i := 0; i < len(a); i++ {
			switch a[i] {
			case "-f":
			case "-d":
				decode = true
			case "-s":
				i++
				if i >= len(a) {
					return fmt.Errorf("missing xdelta source")
				}
				source = a[i]
			default:
				if strings.HasPrefix(a[i], "-") {
					return fmt.Errorf("unsupported xdelta option %s", a[i])
				}
				files = append(files, a[i])
			}
		}
		if !decode || source == "" || len(files) != 2 {
			return fmt.Errorf("invalid xdelta parameters")
		}
		old, err := read(source)
		if err != nil {
			return err
		}
		diff, err := read(files[0])
		if err != nil {
			return err
		}
		out, err := xdelta.Apply(ctx, old, diff)
		if err != nil {
			return err
		}
		dst, err := resolve(files[1])
		if err != nil {
			return err
		}
		slog.Info("xdelta", "src", source, "diff", files[0], "dst", dst, "in", len(old), "out", len(out))
		return put(files[1], out)
	case "x3.exe":
		if len(a) != 1 {
			return fmt.Errorf("invalid RTPatch parameters")
		}
		diff, err := read(a[0])
		if err != nil {
			return err
		}
		records, err := x3.Parse(diff)
		if err != nil {
			return err
		}
		slog.Info("apply update", "patch", a[0], "files", len(records))
		return taskgroup.Each[x3.Record]{
			Name:     "x3",
			PoolKind: taskgroup.CPU,
			Items:    records,
			TaskName: func(_ int, r x3.Record) string { return r.Target },
			Fn: func(ctx context.Context, _ *taskgroup.Status, r x3.Record) error {
				old, err := read(r.Source)
				if err != nil {
					return err
				}
				out, err := r.Apply(ctx, old)
				if err != nil {
					return err
				}
				source, err := resolve(r.Source)
				if err != nil {
					return err
				}
				if err := p.remove(source, false); err != nil {
					return err
				}
				if err := put(r.Target, out); err != nil {
					return err
				}
				slog.Info("x3", "src", r.Source, "dst", r.Target, "in", len(old), "out", len(out))
				return nil
			},
		}.Run(ctx)
	}
	if strings.HasSuffix(name, ".bat") || strings.HasSuffix(name, ".cmd") {
		if len(a) != 0 {
			return fmt.Errorf("parameterized batch recipes are unsupported")
		}
		b, err := read(w[0])
		if err != nil {
			return err
		}
		return p.recipe(ctx, string(b), cwd, depth+1)
	}
	return fmt.Errorf("unsupported reconstruction program %q", w[0])
}

func packingOptions(args []string) (fgpack.Options, string, string, error) {
	o := fgpack.DefaultOptions()
	var files []string
	if len(args) == 2 && !strings.HasPrefix(args[0], "-") && args[0] != "e" {
		return o, args[0], args[1], nil
	}
	if len(args) == 0 || args[0] != "e" {
		return o, "", "", fmt.Errorf("unsupported fgpack operation")
	}
	for _, arg := range args[1:] {
		if !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
			continue
		}
		var dst *int
		prefix := ""
		for key, target := range map[string]*int{"-d": &o.DictLog, "-fb": &o.FastBytes, "-lc": &o.LC, "-lp": &o.LP, "-pb": &o.PB} {
			if strings.HasPrefix(arg, key) {
				prefix = key
				dst = target
				break
			}
		}
		if dst == nil {
			return o, "", "", fmt.Errorf("unsupported fgpack option %q", arg)
		}
		n, err := strconv.Atoi(arg[len(prefix):])
		if err != nil {
			return o, "", "", err
		}
		*dst = n
	}
	if len(files) != 2 {
		return o, "", "", fmt.Errorf("invalid fgpack file parameters")
	}
	return o, files[0], files[1], nil
}

func sevenzArgs(args []string) (string, []string, error) {
	if len(args) == 0 || args[0] != "a" {
		return "", nil, fmt.Errorf("unsupported 7z operation")
	}
	var archive string
	var sources []string
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			switch {
			case arg == "-ms=off", arg == "-mtc=off", arg == "-mtm=off", arg == "-mta=off":
			case strings.HasPrefix(arg, "-m0=lzma"):
			default:
				return "", nil, fmt.Errorf("unsupported 7z option %q", arg)
			}
			continue
		}
		if archive == "" {
			archive = arg
			continue
		}
		sources = append(sources, arg)
	}
	if archive == "" || len(sources) == 0 {
		return "", nil, fmt.Errorf("invalid 7z file parameters")
	}
	return archive, sources, nil
}

func (p *reconstructionPlan) x5n(ctx context.Context, a []string, cwd string) error {
	var files []string
	for i := 0; i < len(a); i++ {
		switch {
		case a[i] == "-f":
		case strings.HasPrefix(a[i], "-s-"):
		case strings.HasPrefix(a[i], "-"):
			return fmt.Errorf("unsupported HDiffPatch option %s", a[i])
		default:
			files = append(files, a[i])
		}
	}
	if len(files) != 3 {
		return fmt.Errorf("unsupported HDiffPatch parameters")
	}
	if files[0] == "." && files[2] == "." {
		return p.x5nDir(ctx, files[1], cwd)
	}
	old, err := p.read(mustVirtual(files[0], cwd))
	if err != nil {
		return err
	}
	diff, err := p.read(mustVirtual(files[1], cwd))
	if err != nil {
		return err
	}
	out, err := x5.Apply(ctx, old, diff)
	if err != nil {
		return err
	}
	return p.put(mustVirtual(files[2], cwd), out)
}

func mustVirtual(name, cwd string) string {
	n, err := virtualPath(name, cwd)
	if err != nil {
		return name
	}
	return n
}

func (p *reconstructionPlan) x5nDir(ctx context.Context, patch, cwd string) error {
	name, err := virtualPath(patch, cwd)
	if err != nil {
		return err
	}
	diff, err := p.read(name)
	if err != nil {
		return err
	}
	info, err := x5n.Parse(diff)
	if err != nil {
		return err
	}
	old := make(map[string][]byte, len(info.OldRefs))
	for _, idx := range info.OldRefs {
		if idx < 0 || idx >= len(info.OldPaths) {
			return fmt.Errorf("x5n: old ref %d", idx)
		}
		rel := info.OldPaths[idx]
		b, err := p.read(mustVirtual(rel, cwd))
		if err != nil {
			return err
		}
		old[rel] = b
	}
	out, err := x5n.Apply(ctx, old, diff)
	if err != nil {
		return err
	}
	for dest, b := range out {
		if err := p.put(mustVirtual(dest, cwd), b); err != nil {
			return err
		}
		slog.Info("x5n", "dst", dest, "out", len(b))
	}
	return nil
}

func (p *reconstructionPlan) x4(a []string, cwd string) error {
	if len(a) != 4 {
		return fmt.Errorf("invalid x4 parameters")
	}
	src, err := virtualPath(a[0], cwd)
	if err != nil {
		return err
	}
	dst, err := virtualPath(a[1], cwd)
	if err != nil {
		return err
	}
	s, rel, err := p.store(src)
	if err != nil {
		return err
	}
	root, _, _ := strings.Cut(src, "/")
	prefix := strings.ToLower(rel)
	p.mu.Lock()
	var matches []string
	for name := range s.files {
		low := strings.ToLower(name)
		if prefix == "" || low == prefix || strings.HasPrefix(low, prefix+"/") {
			matches = append(matches, root+"/"+name)
		}
	}
	p.mu.Unlock()
	var files []x4.File
	for _, m := range matches {
		b, err := p.read(m)
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(m, src+"/")
		if name == m {
			name = lewpath.New(m).Name()
		}
		files = append(files, x4.File{Name: name, Data: b})
	}
	out, err := x4.Pack(files, a[2], a[3])
	if err != nil {
		return err
	}
	slog.Info("x4", "src", src, "dst", dst, "files", len(files), "out", len(out))
	return p.put(dst, out)
}
