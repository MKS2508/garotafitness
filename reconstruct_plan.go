package garotafitness

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"sync"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/taskgroup"
	"github.com/lucasew/garotafitness/internal/scratch"
	"github.com/lucasew/garotafitness/setupdata"
)

type reconstructionPlan struct {
	source     fs.FS
	scratchDir string
	app, temp  *reconstruction
	volumes    map[string]Volume
	remaining  map[string]int
	decoded    map[string]*reconstruction
	seen       map[string]bool
	mu         sync.Mutex
	decodeErr  error
	lastWrite  map[string]taskgroup.ID
	lastUse    map[string]taskgroup.ID
	prior      []taskgroup.ID
	unknown    []taskgroup.ID
	want       map[string][]byte
	hashed     map[string]bool
	ops        []setupdata.Operation
	opi        int
}

func newStaging() *reconstruction {
	return &reconstruction{files: map[string][]byte{}, dirs: map[string]fs.FileMode{}}
}

func (p *reconstructionPlan) stagingCtx(ctx context.Context) context.Context {
	if p == nil || p.scratchDir == "" {
		return ctx
	}
	return scratch.WithDir(ctx, p.scratchDir)
}

// A volume is optional only when every extraction record that uses it is
// optional. The filename convention is only a fallback without a setup record.
func sourceComponents(ops []setupdata.Operation) (map[string]bool, error) {
	optional := map[string]bool{}
	for _, op := range ops {
		if op.Kind != "extract" {
			continue
		}
		source, err := virtualPath(op.Source, "")
		if err != nil {
			return nil, err
		}
		if name, ok := strings.CutPrefix(source, "src/"); ok {
			flag := op.Optional
			if previous, exists := optional[name]; exists {
				flag = flag && previous
			}
			optional[name] = flag
		}
	}
	return optional, nil
}

// virtualPath resolves installer paths inside three disjoint namespaces. Source
// paths can only be read; temporary paths never become installed files.
func virtualPath(name, cwd string) (string, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	lower := strings.ToLower(name)
	expectedRoot := ""
	for _, root := range []string{"app", "tmp", "src"} {
		prefix := "{" + root + "}"
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
			expectedRoot = root
			name = root + "/" + strings.TrimLeft(name[len(prefix):], "/")
			cwd = ""
			break
		}
	}
	if name == "" {
		name = "."
	}
	if strings.ContainsAny(name, ":\x00{}%") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("reconstruction: invalid path %q", name)
	}
	if cwd != "" {
		name = lewpath.New(cwd, name).String()
	} else {
		name = lewpath.New(name).String()
	}
	root, _, _ := strings.Cut(name, "/")
	if expectedRoot != "" && root != expectedRoot {
		return "", fmt.Errorf("reconstruction: path leaves %s namespace", expectedRoot)
	}
	if root != "app" && root != "tmp" && root != "src" {
		return "", fmt.Errorf("reconstruction: path leaves installation: %q", name)
	}
	if cwd != "" {
		base, _, _ := strings.Cut(cwd, "/")
		if root != base {
			return "", fmt.Errorf("reconstruction: path changes namespace: %q", name)
		}
	}
	if !fs.ValidPath(name) {
		return "", fmt.Errorf("reconstruction: invalid path %q", name)
	}
	return name, nil
}

func (p *reconstructionPlan) store(name string) (*reconstruction, string, error) {
	root, rel, _ := strings.Cut(name, "/")
	switch root {
	case "app":
		return p.app, rel, nil
	case "tmp":
		return p.temp, rel, nil
	default:
		return nil, "", fmt.Errorf("reconstruction: cannot write %s", name)
	}
}
func (p *reconstructionPlan) openAt(name string) (io.ReaderAt, io.Closer, int64, error) {
	s, rel, err := p.store(name)
	if err != nil {
		return nil, nil, 0, err
	}
	p.mu.Lock()
	rc, size, err := s.openRead(rel)
	p.mu.Unlock()
	if err != nil {
		return nil, nil, 0, err
	}
	if ra, ok := rc.(io.ReaderAt); ok {
		return ra, rc, size, nil
	}
	b, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return nil, nil, 0, err
	}
	r := bytes.NewReader(b)
	return r, io.NopCloser(r), int64(len(b)), nil
}

func (p *reconstructionPlan) create(name string) (io.WriteCloser, error) {
	s, rel, err := p.store(name)
	if err != nil {
		return nil, err
	}
	return s.Create(rel)
}

func (p *reconstructionPlan) read(name string) ([]byte, error) {
	if strings.HasPrefix(name, "src/") {
		return lewpath.New(strings.TrimPrefix(name, "src/")).ReadFile(p.source)
	}
	s, rel, err := p.store(name)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return s.require(rel)
}
func (p *reconstructionPlan) put(name string, b []byte) error {
	s, rel, err := p.store(name)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if rel == "" || !fs.ValidPath(rel) {
		return fmt.Errorf("reconstruction: invalid file %s", name)
	}
	s.mu.Lock()
	for existing := range s.files {
		if strings.EqualFold(existing, rel) {
			delete(s.files, existing)
			if root := s.fs(); root != nil {
				if pth, err := memberName(existing); err == nil {
					_ = pth.Remove(root)
				}
			}
		}
	}
	s.mu.Unlock()
	return s.putFile(rel, b)
}
func (p *reconstructionPlan) matches(pattern string, dirs bool) ([]string, error) {
	s, rel, err := p.store(pattern)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	root, _, _ := strings.Cut(pattern, "/")
	var out []string
	for name := range s.files {
		ok, err := lewpath.New(strings.ToLower(name)).Match(strings.ToLower(rel))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, root+"/"+name)
		}
	}
	if dirs {
		for name := range s.dirs {
			ok, err := lewpath.New(strings.ToLower(name)).Match(strings.ToLower(rel))
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, root+"/"+name)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}
func (p *reconstructionPlan) remove(name string, tree bool) error {
	s, rel, err := p.store(name)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if rel == "" {
		return fmt.Errorf("reconstruction: cannot remove namespace root")
	}
	for n := range s.files {
		if strings.EqualFold(n, rel) || (tree && strings.HasPrefix(strings.ToLower(n), strings.ToLower(rel)+"/")) {
			delete(s.files, n)
		}
	}
	for n := range s.dirs {
		if strings.EqualFold(n, rel) || (tree && strings.HasPrefix(strings.ToLower(n), strings.ToLower(rel)+"/")) {
			delete(s.dirs, n)
		}
	}
	return nil
}

func (p *reconstructionPlan) extract(ctx context.Context, op setupdata.Operation) error {
	source, err := virtualPath(op.Source, "")
	if err != nil {
		return err
	}
	dest, err := virtualPath(op.Dest, "")
	if err != nil {
		return err
	}
	store, prefix, err := p.store(dest)
	if err != nil {
		return err
	}
	var staged *reconstruction
	if strings.HasPrefix(source, "src/") {
		name := strings.TrimPrefix(source, "src/")
		if _, ok := p.volumes[name]; !ok {
			if op.Optional {
				return nil
			}
			return fmt.Errorf("reconstruction: missing required volume %s", name)
		}
		staged, err = p.waitDecoded(ctx, name)
		if err != nil {
			return err
		}
		p.mu.Lock()
		p.remaining[name]--
		drop := p.remaining[name] <= 0
		if drop {
			delete(p.decoded, name)
		}
		p.mu.Unlock()
		if drop {
			defer staged.Close()
		}
	} else {
		data, err := p.read(source)
		if err != nil {
			return err
		}
		slog.Info("extract reconstructed archive", "name", source)
		staged, err = newDiskStaging(p.stagingCtx(ctx))
		if err != nil {
			return err
		}
		defer staged.Close()
		if err := taskgroup.GoIsolated(ctx, source, taskgroup.Control, func(ctx context.Context, s *taskgroup.Status) error {
			return extractVolumeData(ctx, Extractor{Dest: staged}, source, data, s)
		}); err != nil {
			return err
		}
	}
	filter := strings.Trim(strings.ReplaceAll(op.Filter, "\\", "/"), "/")
	if filter != "" && !fs.ValidPath(filter) {
		return fmt.Errorf("reconstruction: invalid archive filter %q", op.Filter)
	}
	mapName := func(name string) (string, bool) {
		if filter != "" {
			if !strings.HasPrefix(strings.ToLower(name), strings.ToLower(filter)+"/") {
				return "", false
			}
			name = name[len(filter)+1:]
		}
		return lewpath.New(prefix, name).String(), true
	}
	for name, mode := range staged.dirs {
		if mapped, ok := mapName(name); ok {
			if err := store.MkdirAll(mapped, mode); err != nil {
				return err
			}
		}
	}
	var files int
	var nbytes int64
	for name := range staged.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if mapped, ok := mapName(name); ok {
			n, err := store.ingest(ctx, staged, name, mapped)
			if err != nil {
				return err
			}
			files++
			nbytes += n
			slog.Debug("placed", "path", mapped, "size", n, "from", source)
			if dest == "app" || strings.HasPrefix(dest, "app/") {
				p.scheduleHash(ctx, mapped, nil)
			}
		}
	}
	slog.Info("placed archive", "from", source, "to", dest, "filter", filter, "files", files, "bytes", nbytes)
	return nil
}

func (p *reconstructionPlan) run(ctx context.Context, ops []setupdata.Operation) error {
	for _, op := range ops {
		if op.Kind == "extract" {
			source, err := virtualPath(op.Source, "")
			if err != nil {
				return err
			}
			if strings.HasPrefix(source, "src/") {
				p.remaining[strings.TrimPrefix(source, "src/")]++
			}
		}
	}
	p.ops = ops
	for i, op := range ops {
		p.opi = i
		if err := contextError(ctx); err != nil {
			p.mu.Lock()
			if p.decodeErr != nil {
				err = p.decodeErr
			}
			p.mu.Unlock()
			return fmt.Errorf("setup reconstruction record %d: %w", i+1, err)
		}
		slog.Info("reconstruction operation", "index", i+1, "kind", op.Kind, "source", op.Source, "dest", op.Dest, "program", op.Program, "workdir", op.WorkDir)
		var err error
		switch op.Kind {
		case "extract":
			err = p.extract(ctx, op)
		case "command":
			var cwd string
			cwd, err = virtualPath(op.WorkDir, "")
			if err == nil {
				err = p.command(ctx, op.Program, op.Args, cwd, 0)
			}
		case "remove":
			var name string
			name, err = virtualPath(op.Source, "")
			if err == nil {
				err = p.remove(name, true)
			}
		default:
			err = fmt.Errorf("unknown reconstruction operation %q", op.Kind)
		}
		if err != nil {
			return fmt.Errorf("setup reconstruction record %d: %w", i+1, err)
		}
	}
	for name, v := range p.volumes {
		if !v.Optional && !p.seen[name] {
			return fmt.Errorf("setup reconstruction did not extract required volume %s", name)
		}
	}
	return p.finishHashes(ctx)
}

func (p *reconstructionPlan) waitDecoded(ctx context.Context, name string) (*reconstruction, error) {
	p.mu.Lock()
	if p.decodeErr != nil {
		err := p.decodeErr
		p.mu.Unlock()
		return nil, err
	}
	if staged := p.decoded[name]; staged != nil {
		p.seen[name] = true
		p.mu.Unlock()
		return staged, nil
	}
	p.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if _, ok := p.volumes[name]; !ok {
		return nil, fmt.Errorf("reconstruction: missing %s", name)
	}
	slog.Info("extract volume", "name", name)
	staged, err := newDiskStaging(p.stagingCtx(ctx))
	if err != nil {
		return nil, err
	}
	err = taskgroup.GoIsolated(ctx, name, taskgroup.Control, func(ctx context.Context, s *taskgroup.Status) error {
		return extractVolume(ctx, Extractor{Source: p.source, Dest: staged}, p.volumes[name], s)
	})
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		_ = staged.Close()
		err = fmt.Errorf("extract volume %s: %w", name, err)
		if p.decodeErr == nil {
			p.decodeErr = err
		}
		return nil, err
	}
	p.decoded[name] = staged
	p.seen[name] = true
	return staged, nil
}
