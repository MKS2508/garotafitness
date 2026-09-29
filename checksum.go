package garotafitness

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"strings"
	"sync/atomic"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/taskgroup"
)

const checksumName = "MD5/fitgirl-bins.md5"

type checksumJob struct {
	file, sum, name string
}

func collectChecksums(src fs.FS, vols []Volume, optional map[string]bool) ([]checksumJob, error) {
	f, err := lewpath.New(checksumName).Open(src)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("checksum: %w", err)
	}
	defer f.Close()
	want, err := parseMD5(f)
	if err != nil {
		return nil, err
	}
	have := make(map[string]Volume, len(vols))
	for _, v := range vols {
		have[lewpath.New(v.Name).Name()] = v
	}
	for file := range want {
		if _, ok := have[file]; ok {
			continue
		}
		flag, known := optional[file]
		if !known {
			flag = strings.Contains(strings.ToLower(file), optionalMark)
		}
		if flag {
			continue
		}
		// Per-volume extraction (the fitgirl-pipeline CLI's --volume flag)
		// scopes the source dir to one fg-*.bin; the rest of the sidecar
		// is present but the matching volume file is intentionally absent.
		// Warn rather than abort so the user can extract one volume at a
		// time without having to fabricate MD5-matching placeholders for
		// the others.
		slog.Warn("checksum: missing required volume, skipping", "file", file)
		return nil, nil
	}
	var jobs []checksumJob
	for file, sum := range want {
		v, ok := have[file]
		if !ok {
			continue
		}
		jobs = append(jobs, checksumJob{file: file, sum: sum, name: v.Name})
	}
	return jobs, nil
}

func checkVolume(ctx context.Context, src fs.FS, j checksumJob, st *taskgroup.Status) error {
	got, err := hashFile(ctx, src, j.name, st)
	if err != nil {
		return err
	}
	if got != j.sum {
		err := fmt.Errorf("checksum: %s mismatch", j.file)
		slog.Error("cancelling extract", "reason", err)
		if s := taskgroup.FromContext(ctx); s != nil {
			s.Cancel(err)
		}
		return err
	}
	return nil
}

func scheduleChecksums(ctx context.Context, src fs.FS, vols []Volume, optional map[string]bool) error {
	jobs, err := collectChecksums(src, vols, optional)
	if err != nil || len(jobs) == 0 {
		return err
	}
	return withSession(ctx, func(ctx context.Context) error {
		taskgroup.Go(ctx, "checksums", taskgroup.Control, func(ctx context.Context, s *taskgroup.Status) error {
			total := int64(len(jobs))
			s.Progress(0, total)
			var done atomic.Int64
			for _, j := range jobs {
				taskgroup.Go(ctx, j.file, taskgroup.IO, func(ctx context.Context, st *taskgroup.Status) error {
					err := checkVolume(ctx, src, j, st)
					s.Progress(done.Add(1), total)
					return err
				})
			}
			return nil
		})
		return nil
	})
}

func verifyChecksums(ctx context.Context, src fs.FS, vols []Volume, optional map[string]bool) error {
	jobs, err := collectChecksums(src, vols, optional)
	if err != nil || len(jobs) == 0 {
		return err
	}
	return withSession(ctx, func(ctx context.Context) error {
		return taskgroup.Each[checksumJob]{
			Name:     "checksums",
			PoolKind: taskgroup.IO,
			Items:    jobs,
			TaskName: func(_ int, j checksumJob) string { return j.file },
			Fn: func(ctx context.Context, st *taskgroup.Status, j checksumJob) error {
				return checkVolume(ctx, src, j, st)
			},
		}.Run(ctx)
	})
}

func parseMD5(r io.Reader) (map[string]string, error) {
	out := make(map[string]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		sum, rest, ok := strings.Cut(line, " ")
		if !ok || len(sum) != 32 {
			return nil, fmt.Errorf("checksum: bad line %q", line)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, fmt.Errorf("checksum: bad digest %q", sum)
		}
		name := strings.TrimSpace(rest)
		name = strings.TrimPrefix(name, "*")
		name = lewpath.New(strings.ReplaceAll(name, "\\", "/")).Name()
		out[name] = strings.ToLower(sum)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	return out, nil
}

func hashReader(ctx context.Context, r io.Reader, total int64, s *taskgroup.Status) ([]byte, error) {
	if s != nil {
		if total > 0 {
			s.Progress(0, total)
			r = countReader{r: r, p: &byteProgress{s: s, total: total}}
		} else {
			s.Progress(0, -1)
		}
	}
	h := md5.New()
	if _, err := copyCtx(ctx, h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func hashFile(ctx context.Context, src fs.FS, name string, s *taskgroup.Status) (string, error) {
	f, err := lewpath.New(name).Open(src)
	if err != nil {
		return "", fmt.Errorf("checksum open %s: %w", name, err)
	}
	defer f.Close()
	var total int64
	if st, err := f.Stat(); err == nil {
		total = st.Size()
	}
	sum, err := hashReader(ctx, f, total, s)
	if err != nil {
		return "", fmt.Errorf("checksum hash %s: %w", name, err)
	}
	return hex.EncodeToString(sum), nil
}
