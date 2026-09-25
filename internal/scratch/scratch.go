// Package scratch puts extract temps on a directory carried by context.
package scratch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	lewpath "github.com/lewtec/lewkit/x/path"
)

type dirKey struct{}

// WithDir makes MkdirTemp create unique directories under dir/tmp.
// dir is the extract dest OS path. Empty dir leaves MkdirTemp returning an error.
func WithDir(ctx context.Context, dir string) context.Context {
	if dir == "" {
		return ctx
	}
	return context.WithValue(ctx, dirKey{}, dir)
}

// Dir is a unique subdirectory of dest/tmp.
type Dir struct {
	parent *lewpath.Root
	rel    lewpath.Path
	root   *lewpath.Root
}

// Root is the temp directory as an [lewpath.Root].
func (d *Dir) Root() *lewpath.Root {
	if d == nil {
		return nil
	}
	return d.root
}

// Rel is the name of the directory in the WithDir root.
func (d *Dir) Rel() lewpath.Path {
	if d == nil {
		return lewpath.Path{}
	}
	return d.rel
}

// Close removes the directory and closes its roots.
func (d *Dir) Close() error {
	if d == nil {
		return nil
	}
	var err error
	if d.root != nil {
		err = d.root.Close()
		d.root = nil
	}
	if d.parent != nil {
		if rel := d.rel.String(); rel != "" && rel != "." {
			err = errors.Join(err, d.rel.RemoveAll(d.parent))
		}
		err = errors.Join(err, d.parent.Close())
		d.parent = nil
	}
	return err
}

// MkdirTemp creates a unique subdirectory under dest/tmp.
func MkdirTemp(ctx context.Context, pattern string) (*Dir, error) {
	dir, _ := ctx.Value(dirKey{}).(string)
	if dir == "" {
		return nil, errors.New("scratch: no directory (missing WithDir)")
	}
	dest, err := lewpath.Open(dir)
	if err != nil {
		return nil, err
	}
	tmp := lewpath.New("tmp")
	if err := tmp.MkdirAll(dest, 0o755); err != nil {
		dest.Close()
		return nil, err
	}
	for range 10000 {
		name, err := tempName(pattern)
		if err != nil {
			dest.Close()
			return nil, err
		}
		p := tmp.Join(name)
		if !p.Valid() || p.IsAbs() || p.Parent().String() != "tmp" {
			dest.Close()
			return nil, fmt.Errorf("scratch: invalid pattern %q", pattern)
		}
		if err := p.Mkdir(dest, 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			dest.Close()
			return nil, err
		}
		child, err := p.OpenRoot(dest)
		if err != nil {
			_ = p.RemoveAll(dest)
			dest.Close()
			return nil, err
		}
		return &Dir{parent: dest, rel: p, root: child}, nil
	}
	dest.Close()
	return nil, errors.New("scratch: unique name")
}

func tempName(pattern string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	suffix := hex.EncodeToString(b[:])
	before, after, found := strings.CutLast(pattern, "*")
	if found {
		return before + suffix + after, nil
	}
	return pattern + suffix, nil
}
