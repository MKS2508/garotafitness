package garotafitness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/lucasew/garotafitness/setupdata"
)

// InspectReport is volume pipelines, registered codecs, and matcher hits.
type InspectReport struct {
	Volumes []InspectVolume
	Codecs  []InspectCodec
	Tools   []InspectTool
}

// InspectVolume is one fg-*.bin and the pipelines its members use.
type InspectVolume struct {
	Name, Pipeline string
	Files          int
	Size           int64
}

// InspectCodec is one registered reconstruct codec.
type InspectCodec struct {
	Name, ID, SHA256 string
}

// InspectTool is an unpacked installer exe and how the matcher classified it.
type InspectTool struct {
	Name, SHA256, Match string
	Size                int64
}

// Inspect reads setup.exe, unpacks installer tool volumes, and reports
// pipelines, registered codecs, and matcher results.
func Inspect(ctx context.Context, src fs.FS) (InspectReport, error) {
	if src == nil {
		return InspectReport{}, fmt.Errorf("nil source")
	}
	setup, err := readSetup(src)
	if err != nil {
		return InspectReport{}, fmt.Errorf("setup.exe: %w", err)
	}
	vols, err := listVolumes(src)
	if err != nil {
		vols = nil
	}
	pipes, err := inspectVolumePipes(src, vols)
	if err != nil {
		return InspectReport{}, err
	}
	rep := InspectReport{Volumes: pipes, Codecs: reconstructToolset.list()}
	staged, err := unpackTmp(ctx, src, setup.Operations, vols)
	if err != nil || staged == nil {
		return rep, err
	}
	defer staged.Close()
	rep.Tools, err = inspectTools(staged)
	return rep, err
}

func unpackTmp(ctx context.Context, src fs.FS, ops []setupdata.Operation, vols []Volume) (*reconstruction, error) {
	names := tmpVolumeNames(ops)
	if len(names) == 0 {
		return nil, nil
	}
	if len(vols) == 0 {
		return nil, fmt.Errorf("inspect: no fg-*.bin")
	}
	have := map[string]Volume{}
	for _, v := range vols {
		have[v.Name] = v
	}
	staged := newStaging()
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			staged.Close()
			return nil, err
		}
		v, ok := have[name]
		if !ok {
			staged.Close()
			return nil, fmt.Errorf("inspect: missing volume %s", name)
		}
		slog.Info("inspect volume", "name", name)
		if err := extractVolume(ctx, Extractor{Source: src, Dest: staged}, v, nil); err != nil {
			staged.Close()
			return nil, fmt.Errorf("inspect %s: %w", name, err)
		}
	}
	return staged, nil
}

func (s *toolset) list() []InspectCodec {
	var out []InspectCodec
	for _, h := range slices.Sorted(maps.Keys(s.byHash)) {
		c := s.byHash[h]
		name := c.id
		if len(c.names) > 0 {
			name = c.names[0]
		}
		out = append(out, InspectCodec{Name: name, ID: c.id, SHA256: c.sha256})
	}
	slices.SortFunc(out, func(a, b InspectCodec) int {
		if n := strings.Compare(a.Name, b.Name); n != 0 {
			return n
		}
		if n := strings.Compare(a.ID, b.ID); n != 0 {
			return n
		}
		return strings.Compare(a.SHA256, b.SHA256)
	})
	return out
}

func (s *toolset) describe(name, digest string) string {
	c, err := s.match(name, digest)
	switch {
	case err == nil && digest == "":
		return c.id + " (name)"
	case err == nil:
		return c.id + " (hash)"
	case errors.Is(err, errUnknownToolHash):
		return "checksum"
	default:
		return "unregistered"
	}
}

func tmpVolumeNames(ops []setupdata.Operation) []string {
	var names []string
	seen := map[string]bool{}
	for _, op := range ops {
		if op.Kind != "extract" {
			continue
		}
		dest, err := virtualPath(op.Dest, "")
		if err != nil || (dest != "tmp" && !strings.HasPrefix(dest, "tmp/")) {
			continue
		}
		src, err := virtualPath(op.Source, "")
		if err != nil || !strings.HasPrefix(src, "src/") {
			continue
		}
		name := strings.TrimPrefix(src, "src/")
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

func inspectVolumePipes(src fs.FS, vols []Volume) ([]InspectVolume, error) {
	out := make([]InspectVolume, 0, len(vols))
	for _, v := range vols {
		f, err := src.Open(v.Name)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		ra, ok := f.(io.ReaderAt)
		if !ok {
			f.Close()
			return nil, fmt.Errorf("inspect: %s: not readable at", v.Name)
		}
		parsed, err := parseVolumeAt(v.Name, ra, st.Size())
		f.Close()
		if err != nil {
			return nil, err
		}
		pipes := map[string]int{}
		files := 0
		for _, m := range parsed.Members {
			if m.Dir {
				continue
			}
			files++
			pipes[m.Pipeline.String()]++
		}
		names := slices.Sorted(maps.Keys(pipes))
		out = append(out, InspectVolume{Name: v.Name, Pipeline: strings.Join(names, ", "), Files: files, Size: st.Size()})
	}
	slices.SortFunc(out, func(a, b InspectVolume) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func inspectTools(staged *reconstruction) ([]InspectTool, error) {
	staged.mu.Lock()
	names := slices.Sorted(maps.Keys(staged.files))
	staged.mu.Unlock()
	var out []InspectTool
	for _, name := range names {
		if !strings.EqualFold(path.Ext(name), ".exe") {
			continue
		}
		b, err := staged.require(name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		base := strings.ToLower(path.Base(name))
		out = append(out, InspectTool{
			Name:   base,
			Size:   int64(len(b)),
			SHA256: digest,
			Match:  reconstructToolset.describe(base, digest),
		})
	}
	slices.SortFunc(out, func(a, b InspectTool) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
