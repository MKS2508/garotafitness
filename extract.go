package garotafitness

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"slices"
	"sync"

	"github.com/lewtec/lewkit/x/taskgroup"
	"github.com/lucasew/garotafitness/internal/pages"
	"github.com/lucasew/garotafitness/setupdata"
)

// Extractor reads Source and writes Dest.
type Extractor struct {
	Source fs.FS
	Dest   Dest
}

func (e Extractor) Extract(ctx context.Context) error {
	if e.Source == nil {
		return fmt.Errorf("nil source")
	}
	if e.Dest == nil {
		return fmt.Errorf("nil dest")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return withSession(ctx, e.extract)
}

func (e Extractor) extract(ctx context.Context) error {
	setup, setupErr := readSetup(e.Source)
	if err := setupErr; err != nil {
		return fmt.Errorf("setup.exe: %w", err)
	} else if len(setup.Encoders) > 0 {
		slog.Info("setup encoders", "names", setup.Encoders)
	}
	if n := len(setup.Operations); n > 0 {
		slog.Info("setup reconstruction records", "count", n)
	}
	optional, err := sourceComponents(setup.Operations)
	if err != nil {
		return err
	}
	vols, err := listVolumes(e.Source)
	if err != nil {
		return err
	}
	slog.Info("volumes", "count", len(vols))
	for i := range vols {
		if flag, ok := optional[vols[i].Name]; ok {
			vols[i].Optional = flag
		}
	}
	if err := scheduleChecksums(ctx, e.Source, vols, optional); err != nil {
		return err
	}
	if setup.InstalledMD5 != "" || len(setup.Operations) != 0 {
		slog.Info("reconstruct from setup metadata")
		return e.extractReconstructed(ctx, vols, setup)
	}
	return extractVolumes(ctx, e, vols)
}

func fileSize(src fs.FS, name string) int64 {
	fi, err := fs.Stat(src, name)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func sortVolumesBySize(src fs.FS, vols []Volume) {
	slices.SortFunc(vols, func(a, b Volume) int {
		return cmp.Compare(fileSize(src, b.Name), fileSize(src, a.Name))
	})
}

func extractVolumes(ctx context.Context, e Extractor, vols []Volume) error {
	sortVolumesBySize(e.Source, vols)
	return withSession(ctx, func(ctx context.Context) error {
		return taskgroup.Each[Volume]{
			Name:     "volumes",
			PoolKind: taskgroup.Control,
			Serial:   true,
			Items:    vols,
			TaskName: func(_ int, v Volume) string { return v.Name },
			Fn: func(ctx context.Context, s *taskgroup.Status, v Volume) error {
				return extractVolume(ctx, e, v, s)
			},
		}.Run(ctx)
	})
}

func scanSetup(src fs.FS) ([]string, error) {
	info, err := readSetup(src)
	return info.Encoders, err
}

func readSetup(src fs.FS) (setupdata.Info, error) {
	f, err := src.Open("setup.exe")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return setupdata.Info{}, nil
		}
		return setupdata.Info{}, err
	}
	defer f.Close()
	return setupdata.Scan(f)
}

type byteProgress struct {
	s           *taskgroup.Status
	done, total int64
}

func (p *byteProgress) add(n int64) {
	if p == nil || p.s == nil || p.total <= 0 {
		return
	}
	p.done += n
	p.s.Progress(p.done, p.total)
}

func (p *byteProgress) member(name string) {
	if p == nil || p.s == nil {
		return
	}
	p.s.Update(name)
}

type countReader struct {
	r io.Reader
	p *byteProgress
}

func (c countReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.p.add(int64(n))
	return n, err
}

// spanAt reports the highest ReadAt offset inside [base, base+lim).
type spanAt struct {
	ra        io.ReaderAt
	base, lim int64
	s         *taskgroup.Status
	mu        sync.Mutex
	max       int64
}

func (t *spanAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := t.ra.ReadAt(p, off)
	if n > 0 && t.s != nil && off >= t.base {
		end := off - t.base + int64(n)
		if end > t.lim {
			end = t.lim
		}
		t.mu.Lock()
		if end > t.max {
			t.max = end
			t.s.Progress(t.max, t.lim)
		}
		t.mu.Unlock()
	}
	return n, err
}

func asReaderAt(f fs.File) (io.ReaderAt, int64, bool) {
	ra, ok := f.(io.ReaderAt)
	if !ok {
		return nil, 0, false
	}
	st, err := f.Stat()
	if err != nil {
		return nil, 0, false
	}
	return ra, st.Size(), true
}

func extractVolume(ctx context.Context, e Extractor, v Volume, st *taskgroup.Status) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	f, err := e.Source.Open(v.Name)
	if err != nil {
		return fmt.Errorf("open %s: %w", v.Name, err)
	}
	defer f.Close()
	ra, size, ok := asReaderAt(f)
	if !ok {
		data, err := io.ReadAll(ctxReader{ctx, f})
		if err != nil {
			return fmt.Errorf("read %s: %w", v.Name, err)
		}
		ra = bytes.NewReader(data)
		size = int64(len(data))
	}
	slog.Info("open volume", "name", v.Name, "bytes", size)
	return extractVolumeAt(ctx, e, v.Name, ra, size, st)
}

func extractVolumeData(ctx context.Context, e Extractor, name string, data []byte, st *taskgroup.Status) error {
	return extractVolumeAt(ctx, e, name, bytes.NewReader(data), int64(len(data)), st)
}

func extractVolumeAt(ctx context.Context, e Extractor, name string, ra io.ReaderAt, size int64, st *taskgroup.Status) error {
	parsed, err := parseVolumeAt(name, ra, size)
	if err != nil {
		return err
	}
	var total int64
	for _, m := range parsed.Members {
		if m.Dir {
			if err := e.Dest.MkdirAll(m.Path, 0o755); err != nil {
				return err
			}
			continue
		}
		total += int64(m.Size)
	}
	err = extractSolids(ctx, e, ra, groupSolids(parsed.Members))
	if err != nil {
		return err
	}
	var files int
	for _, m := range parsed.Members {
		if !m.Dir {
			files++
		}
	}
	slog.Info("extracted volume", "name", name, "compressed", size, "uncompressed", total, "files", files)
	return nil
}

func extractSolids(ctx context.Context, e Extractor, ra io.ReaderAt, solids iter.Seq[solid]) error {
	var list []solid
	for s := range solids {
		list = append(list, s)
	}
	if len(list) == 0 {
		return nil
	}
	slices.SortFunc(list, func(a, b solid) int {
		if c := cmp.Compare(b.csz, a.csz); c != 0 {
			return c
		}
		var as, bs uint64
		for _, m := range a.files {
			as += m.Size
		}
		for _, m := range b.files {
			bs += m.Size
		}
		return cmp.Compare(bs, as)
	})
	return withSession(ctx, func(ctx context.Context) error {
		return taskgroup.Each[solid]{
			Name:     "solids",
			PoolKind: taskgroup.CPU,
			Items:    list,
			TaskName: func(_ int, s solid) string { return s.pipe.String() },
			Fn: func(ctx context.Context, st *taskgroup.Status, s solid) error {
				if s.csz > 0 {
					st.Progress(0, int64(s.csz))
				}
				return extractSolid(ctx, e, ra, s, &byteProgress{s: st})
			},
		}.Run(ctx)
	})
}

type solid struct {
	pipe  Pipeline
	off   int64
	csz   uint64
	files []Member
}

func groupSolids(ms []Member) iter.Seq[solid] {
	return func(yield func(solid) bool) {
		type key struct {
			pipe string
			off  int64
			csz  uint64
		}
		order := make([]key, 0)
		by := make(map[key]*solid)
		for _, m := range ms {
			if m.Dir {
				continue
			}
			k := key{m.Pipeline.String(), m.Offset, m.CompSize}
			s, ok := by[k]
			if !ok {
				s = &solid{pipe: m.Pipeline, off: m.Offset, csz: m.CompSize}
				by[k] = s
				order = append(order, k)
			}
			s.files = append(s.files, m)
		}
		for _, k := range order {
			if !yield(*by[k]) {
				return
			}
		}
	}
}

func extractSolid(ctx context.Context, e Extractor, ra io.ReaderAt, s solid, prog *byteProgress) error {
	if len(s.files) == 0 {
		return nil
	}
	if len(s.pipe) == 0 {
		return unknownEncoderError(Atom{})
	}
	slog.Info("decode solid", "pipeline", s.pipe.String(), "offset", s.off, "compressed", s.csz, "members", len(s.files))
	if s.off < 0 {
		return fmt.Errorf("solid span")
	}
	ra = ctxAt{ctx: ctx, ra: ra}
	if prog != nil && prog.s != nil && s.csz > 0 {
		ra = &spanAt{ra: ra, base: s.off, lim: int64(s.csz), s: prog.s}
	}
	var (
		src     io.Reader = io.NewSectionReader(ra, s.off, int64(s.csz))
		closers []io.Closer
	)
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i].Close()
		}
	}()
	for i := len(s.pipe) - 1; i >= 0; i-- {
		r, err := Decode(ctx, src, s.pipe[i])
		if err != nil {
			return fmt.Errorf("open %s in pipeline %s (solid offset %d compressed %d): %w",
				s.pipe[i], s.pipe.String(), s.off, s.csz, err)
		}
		closers = append(closers, r)
		src = r
	}
	if prog != nil && prog.s != nil {
		prog.s.Update(s.pipe.String())
	}
	err := withSession(ctx, func(ctx context.Context) error {
		return taskgroup.Isolate(ctx, func(ctx context.Context) error {
			sem := make(chan struct{}, 4)
			for _, m := range s.files {
				if err := contextError(ctx); err != nil {
					return err
				}
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return contextError(ctx)
				}
				prog.member(m.Path)
				buf, err := pages.Read(src, int64(m.Size))
				if err != nil {
					<-sem
					return fmt.Errorf("extract %s pipeline %s (solid offset %d compressed %d): %w",
						m.Path, s.pipe.String(), s.off, s.csz, err)
				}
				taskgroup.Go(ctx, m.Path, taskgroup.IO, func(ctx context.Context, st *taskgroup.Status) error {
					defer buf.Release()
					defer func() { <-sem }()
					if m.Size > 0 {
						st.Progress(0, int64(m.Size))
					}
					if err := writeMember(ctx, e.Dest, m, buf.Reader()); err != nil {
						return fmt.Errorf("extract %s pipeline %s (solid offset %d compressed %d): %w",
							m.Path, s.pipe.String(), s.off, s.csz, err)
					}
					if m.Size > 0 {
						st.Progress(int64(m.Size), int64(m.Size))
					}
					slog.Debug("extracted", "path", m.Path, "size", m.Size, "pipeline", s.pipe.String())
					return nil
				})
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	var extra [1]byte
	if _, err := io.ReadFull(src, extra[:]); err != io.EOF {
		if err != nil {
			return fmt.Errorf("finish solid: %w", err)
		}
		return fmt.Errorf("solid contains data after its final member")
	}
	var uncompressed uint64
	for _, m := range s.files {
		uncompressed += m.Size
	}
	slog.Info("extracted solid", "pipeline", s.pipe.String(), "members", len(s.files), "compressed", s.csz, "uncompressed", uncompressed)
	return nil
}

func writeMember(ctx context.Context, dst Dest, m Member, r io.Reader) error {
	w, err := dst.Create(m.Path)
	if err != nil {
		return err
	}
	table := m.crcTable
	if table == nil {
		table = crc32.IEEETable
	}
	h := crc32.New(table)
	n, err := copyCtx(ctx, w, io.TeeReader(r, h))
	if err != nil {
		w.Close()
		return fmt.Errorf("decode %s: %w", m.Path, err)
	}
	if err := w.Close(); err != nil {
		return err
	}
	if uint64(n) != m.Size {
		return fmt.Errorf("write %s: size %d want %d", m.Path, n, m.Size)
	}
	if (m.crcTable != nil || m.CRC != 0) && h.Sum32() != m.CRC {
		return fmt.Errorf("write %s: crc %08x want %08x", m.Path, h.Sum32(), m.CRC)
	}
	slog.Debug("wrote member", "path", m.Path, "size", n, "crc", fmt.Sprintf("%08x", h.Sum32()))
	return nil
}
