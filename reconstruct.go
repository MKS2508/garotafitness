package garotafitness

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/taskgroup"
	"github.com/lucasew/garotafitness/setupdata"
)

// reconstruction holds extract intermediates until Dest is written.
// dir set: file bodies live on disk (FS25-sized trees). dir empty: tests keep []byte.
type reconstruction struct {
	mu    sync.Mutex
	dir   string
	files map[string][]byte
	dirs  map[string]fs.FileMode
}

func newDiskStaging() (*reconstruction, error) {
	dir, err := os.MkdirTemp("", "garotafitness-stage-*")
	if err != nil {
		return nil, err
	}
	return &reconstruction{dir: dir, files: map[string][]byte{}, dirs: map[string]fs.FileMode{}}, nil
}

func (s *reconstruction) Close() error {
	if s == nil || s.dir == "" {
		return nil
	}
	dir := s.dir
	s.dir = ""
	return os.RemoveAll(dir)
}

func (s *reconstruction) diskPath(name string) (string, error) {
	p, err := memberName(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, filepath.FromSlash(p.String())), nil
}

func (s *reconstruction) lookup(name string) (string, []byte, error) {
	if b, ok := s.files[name]; ok {
		return name, b, nil
	}
	found := ""
	var data []byte
	for candidate, b := range s.files {
		if strings.EqualFold(candidate, name) {
			if found != "" {
				return "", nil, fmt.Errorf("reconstruction: ambiguous filename %s", name)
			}
			found, data = candidate, b
		}
	}
	if found == "" {
		return "", nil, fmt.Errorf("reconstruction: missing %s", name)
	}
	return found, data, nil
}

func (s *reconstruction) MkdirAll(name string, mode fs.FileMode) error {
	if _, err := memberName(name); err != nil {
		return err
	}
	s.mu.Lock()
	s.dirs[name] = mode
	s.mu.Unlock()
	return nil
}

func (s *reconstruction) Create(name string) (io.WriteCloser, error) {
	if _, err := memberName(name); err != nil {
		return nil, err
	}
	if s.dir != "" {
		p, err := s.diskPath(name)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, err
		}
		f, err := os.Create(p)
		if err != nil {
			return nil, err
		}
		return &diskStaged{File: f, store: s, name: name}, nil
	}
	return &stagedFile{store: s, name: name}, nil
}

type stagedFile struct {
	bytes.Buffer
	store *reconstruction
	name  string
}

func (f *stagedFile) Close() error {
	f.store.mu.Lock()
	f.store.files[f.name] = f.Bytes()
	f.store.mu.Unlock()
	return nil
}

type diskStaged struct {
	*os.File
	store *reconstruction
	name  string
}

func (f *diskStaged) Close() error {
	err := f.File.Close()
	f.store.mu.Lock()
	f.store.files[f.name] = nil
	f.store.mu.Unlock()
	return err
}

func (s *reconstruction) putFile(name string, b []byte) error {
	if _, err := memberName(name); err != nil {
		return err
	}
	if s.dir != "" {
		p, err := s.diskPath(name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
		s.mu.Lock()
		s.files[name] = nil
		s.mu.Unlock()
		return nil
	}
	s.mu.Lock()
	s.files[name] = b
	s.mu.Unlock()
	return nil
}

func (s *reconstruction) require(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, b, err := s.lookup(name)
	if err != nil {
		return nil, err
	}
	if s.dir != "" {
		p, err := s.diskPath(key)
		if err != nil {
			return nil, err
		}
		return os.ReadFile(p)
	}
	return b, nil
}

func (s *reconstruction) ingest(ctx context.Context, src *reconstruction, srcName, dstName string) (int64, error) {
	if _, err := memberName(dstName); err != nil {
		return 0, err
	}
	if s.dir == "" && src.dir == "" {
		b, err := src.require(srcName)
		if err != nil {
			return 0, err
		}
		s.mu.Lock()
		s.files[dstName] = b
		s.mu.Unlock()
		return int64(len(b)), nil
	}
	r, n, err := src.openRead(srcName)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	if s.dir != "" {
		p, err := s.diskPath(dstName)
		if err != nil {
			return 0, err
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return 0, err
		}
		w, err := os.Create(p)
		if err != nil {
			return 0, err
		}
		copied, err := copyCtx(ctx, w, r)
		closeErr := w.Close()
		if err != nil {
			return copied, err
		}
		s.mu.Lock()
		s.files[dstName] = nil
		s.mu.Unlock()
		return copied, closeErr
	}
	b, err := io.ReadAll(ctxReader{ctx, r})
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.files[dstName] = b
	s.mu.Unlock()
	if n < 0 {
		n = int64(len(b))
	}
	return n, nil
}

func (s *reconstruction) openRead(name string) (io.ReadCloser, int64, error) {
	s.mu.Lock()
	key, b, err := s.lookup(name)
	dir := s.dir
	s.mu.Unlock()
	if err != nil {
		return nil, 0, err
	}
	if dir != "" {
		p, err := s.diskPath(key)
		if err != nil {
			return nil, 0, err
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, 0, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, 0, err
		}
		return f, st.Size(), nil
	}
	return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
}

func (e Extractor) extractReconstructed(ctx context.Context, vols []Volume, setup setupdata.Info) error {
	s, err := newDiskStaging()
	if err != nil {
		return err
	}
	defer s.Close()
	temp, err := newDiskStaging()
	if err != nil {
		return err
	}
	defer temp.Close()
	runner := &reconstructionPlan{source: e.Source, app: s, temp: temp, volumes: map[string]Volume{}, remaining: map[string]int{}, decoded: map[string]*reconstruction{}, seen: map[string]bool{}}
	for _, v := range vols {
		runner.volumes[v.Name] = v
	}
	manifestPath := ""
	if setup.InstalledMD5 != "" {
		if setup.ManifestPath == "" {
			return fmt.Errorf("installed checksum: unresolved destination in setup metadata")
		}
		name, err := virtualPath(setup.ManifestPath, "")
		if err != nil {
			return err
		}
		if !strings.HasPrefix(name, "app/") {
			return fmt.Errorf("installed checksum: destination outside installed files")
		}
		manifestPath = strings.TrimPrefix(name, "app/")
		if err := s.putFile(manifestPath, []byte(setup.InstalledMD5)); err != nil {
			return err
		}
		want, err := parseInstalledWant(setup.InstalledMD5, lewpath.New(manifestPath).Parent().String())
		if err != nil {
			return err
		}
		runner.want = want
		runner.hashed = map[string]bool{}
	}
	if len(setup.Operations) > 0 {
		if err := runner.run(ctx, setup.Operations); err != nil {
			return err
		}
	} else {
		if err := extractVolumes(ctx, Extractor{Source: e.Source, Dest: s}, vols); err != nil {
			return err
		}
	}
	if len(runner.want) > 0 {
		slog.Info("verify installed checksums", "manifest", manifestPath, "files", len(runner.want))
		if err := runner.finishHashes(ctx); err != nil {
			return err
		}
	}
	slog.Info("write reconstructed tree", "dirs", len(s.dirs), "files", len(s.files))
	for name := range sortedKeys(s.dirs) {
		if err := e.Dest.MkdirAll(name, s.dirs[name]); err != nil {
			return err
		}
	}
	names := slices.Collect(sortedKeys(s.files))
	err = withSession(ctx, func(ctx context.Context) error {
		return taskgroup.Each[string]{
			Name:     "write dest",
			PoolKind: taskgroup.IO,
			Items:    names,
			TaskName: func(_ int, name string) string { return name },
			Fn: func(ctx context.Context, st *taskgroup.Status, name string) error {
				defer st.Unit()()
				r, n, err := s.openRead(name)
				if err != nil {
					return err
				}
				defer r.Close()
				return writeMember(ctx, e.Dest, Member{Path: name, Size: uint64(n)}, r)
			},
		}.Run(ctx)
	})
	if err != nil {
		return err
	}
	s.files = map[string][]byte{}
	return nil
}

func sortedKeys[V any](m map[string]V) iter.Seq[string] {
	return slices.Values(slices.Sorted(maps.Keys(m)))
}

func parseInstalledWant(manifest, directory string) (map[string][]byte, error) {
	want := map[string][]byte{}
	sc := bufio.NewScanner(strings.NewReader(manifest))
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if len(line) < 35 || line[32] != ' ' || (line[33] != '*' && line[33] != ' ') {
			return nil, fmt.Errorf("installed checksum: invalid manifest line")
		}
		resolved, err := virtualPath(line[34:], lewpath.New("app", directory).String())
		if err != nil {
			return nil, fmt.Errorf("installed checksum: %w", err)
		}
		sum, err := hex.DecodeString(line[:32])
		if err != nil {
			return nil, fmt.Errorf("installed checksum: %w", err)
		}
		want[strings.TrimPrefix(resolved, "app/")] = sum
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(want) == 0 {
		return nil, fmt.Errorf("installed checksum: empty manifest")
	}
	return want, nil
}

func (s *reconstruction) verifyInstalled(ctx context.Context, manifest, directory string) error {
	want, err := parseInstalledWant(manifest, directory)
	if err != nil {
		return err
	}
	type job struct {
		name string
		want []byte
	}
	jobs := make([]job, 0, len(want))
	for name, sum := range want {
		jobs = append(jobs, job{name: name, want: sum})
	}
	err = withSession(ctx, func(ctx context.Context) error {
		return taskgroup.Each[job]{
			Name:     "verify",
			PoolKind: taskgroup.CPU,
			Items:    jobs,
			TaskName: func(_ int, j job) string { return j.name },
			Fn: func(ctx context.Context, st *taskgroup.Status, j job) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				r, n, err := s.openRead(j.name)
				if err != nil {
					return err
				}
				defer r.Close()
				got, err := hashReader(ctx, r, n, st)
				if err != nil {
					return err
				}
				if !bytes.Equal(got, j.want) {
					return fmt.Errorf("installed checksum: %s: %x want %x", j.name, got, j.want)
				}
				return nil
			},
		}.Run(ctx)
	})
	if err != nil {
		return err
	}
	slog.Info("installed hashes verified", "files", len(jobs))
	return nil
}
