// Package x5n applies HDIFF19 directory patches used by the installer's x5n step.
package x5n

import (
	"fmt"
	"strings"
)

// DirDiff is a parsed HDIFF19 directory patch.
type DirDiff struct {
	OldPaths    []string
	NewPaths    []string
	OldRefs     []int
	NewRefs     []int
	NewRefSizes []uint64
	OldRefSize  uint64
	NewRefSize  uint64
	Inner       []byte
}

func unpackUInt(b []byte) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, b, fmt.Errorf("x5n: truncated integer")
	}
	code := b[0]
	b = b[1:]
	value := uint64(code & 0x7f)
	if code&0x80 == 0 {
		return value, b, nil
	}
	for {
		if len(b) == 0 {
			return 0, b, fmt.Errorf("x5n: truncated integer")
		}
		code = b[0]
		b = b[1:]
		if value>>(64-7) != 0 {
			return 0, b, fmt.Errorf("x5n: integer overflow")
		}
		value = (value << 7) | uint64(code&0x7f)
		if code&0x80 == 0 {
			return value, b, nil
		}
	}
}

func readType(b []byte, end byte) (string, []byte, error) {
	for i, c := range b {
		if c == end {
			return string(b[:i]), b[i+1:], nil
		}
		if c == 0 && end != 0 {
			return "", b, fmt.Errorf("x5n: unexpected end in type")
		}
	}
	return "", b, fmt.Errorf("x5n: missing type delimiter")
}

func readIncList(b []byte, count, limit int) ([]int, []byte, error) {
	out := make([]int, count)
	back := uint64(^uint64(0))
	for i := range out {
		inc, rest, err := unpackUInt(b)
		if err != nil {
			return nil, b, err
		}
		b = rest
		back += 1 + inc
		if back >= uint64(limit) {
			return nil, b, fmt.Errorf("x5n: index %d out of range", back)
		}
		out[i] = int(back)
	}
	return out, b, nil
}

func splitCStrings(data []byte, n int) ([]string, error) {
	out := make([]string, 0, n)
	start := 0
	for i, c := range data {
		if c != 0 {
			continue
		}
		out = append(out, string(data[start:i]))
		start = i + 1
	}
	if start != len(data) || len(out) != n {
		return nil, fmt.Errorf("x5n: path list %d want %d", len(out), n)
	}
	return out, nil
}

// Parse reads an HDIFF19 directory patch with an empty compress type.
func Parse(data []byte) (*DirDiff, error) {
	typ, rest, err := readType(data, '&')
	if err != nil {
		return nil, err
	}
	if typ != "HDIFF19" {
		return nil, fmt.Errorf("x5n: unsupported type %q", typ)
	}
	comp, rest, err := readType(rest, '&')
	if err != nil {
		return nil, err
	}
	if comp != "" {
		return nil, fmt.Errorf("x5n: compressed directory head %q", comp)
	}
	sum, rest, err := readType(rest, 0)
	if err != nil {
		return nil, err
	}
	if sum != "fadler64" && sum != "" {
		return nil, fmt.Errorf("x5n: unsupported checksum %q", sum)
	}
	u := func() (uint64, error) {
		var v uint64
		v, rest, err = unpackUInt(rest)
		return v, err
	}
	oldDir, err := u()
	if err != nil {
		return nil, err
	}
	newDir, err := u()
	if err != nil {
		return nil, err
	}
	if oldDir > 1 || newDir > 1 {
		return nil, fmt.Errorf("x5n: invalid directory flags")
	}
	oldPathCount, err := u()
	if err != nil {
		return nil, err
	}
	oldPathSum, err := u()
	if err != nil {
		return nil, err
	}
	newPathCount, err := u()
	if err != nil {
		return nil, err
	}
	newPathSum, err := u()
	if err != nil {
		return nil, err
	}
	oldRefCount, err := u()
	if err != nil {
		return nil, err
	}
	oldRefSize, err := u()
	if err != nil {
		return nil, err
	}
	newRefCount, err := u()
	if err != nil {
		return nil, err
	}
	newRefSize, err := u()
	if err != nil {
		return nil, err
	}
	sameCount, err := u()
	if err != nil {
		return nil, err
	}
	if _, err = u(); err != nil { // sameFileSize
		return nil, err
	}
	execCount, err := u()
	if err != nil {
		return nil, err
	}
	if _, err = u(); err != nil { // privateReserved
		return nil, err
	}
	privExtern, err := u()
	if err != nil {
		return nil, err
	}
	externSize, err := u()
	if err != nil {
		return nil, err
	}
	headSize, err := u()
	if err != nil {
		return nil, err
	}
	headCompressed, err := u()
	if err != nil {
		return nil, err
	}
	if headCompressed != 0 {
		return nil, fmt.Errorf("x5n: compressed directory head")
	}
	checksumBytes, err := u()
	if err != nil {
		return nil, err
	}
	if uint64(len(rest)) < checksumBytes*4 {
		return nil, fmt.Errorf("x5n: truncated checksums")
	}
	rest = rest[checksumBytes*4:]
	if uint64(len(rest)) < headSize {
		return nil, fmt.Errorf("x5n: truncated head")
	}
	head := rest[:headSize]
	rest = rest[headSize:]
	if uint64(len(rest)) < privExtern+externSize {
		return nil, fmt.Errorf("x5n: truncated extern")
	}
	inner := rest[privExtern+externSize:]
	pathSum := oldPathSum + newPathSum
	if uint64(len(head)) < pathSum {
		return nil, fmt.Errorf("x5n: truncated paths")
	}
	paths, err := splitCStrings(head[:pathSum], int(oldPathCount+newPathCount))
	if err != nil {
		return nil, err
	}
	cur := head[pathSum:]
	oldRefs, cur, err := readIncList(cur, int(oldRefCount), int(oldPathCount))
	if err != nil {
		return nil, err
	}
	newRefs, cur, err := readIncList(cur, int(newRefCount), int(newPathCount))
	if err != nil {
		return nil, err
	}
	sizes := make([]uint64, newRefCount)
	for i := range sizes {
		sizes[i], cur, err = unpackUInt(cur)
		if err != nil {
			return nil, err
		}
	}
	if sameCount != 0 || execCount != 0 {
		return nil, fmt.Errorf("x5n: same-file or execute lists are unsupported")
	}
	return &DirDiff{
		OldPaths:    paths[:oldPathCount],
		NewPaths:    paths[oldPathCount:],
		OldRefs:     oldRefs,
		NewRefs:     newRefs,
		NewRefSizes: sizes,
		OldRefSize:  oldRefSize,
		NewRefSize:  newRefSize,
		Inner:       inner,
	}, nil
}

func isDirPath(name string) bool {
	return name == "" || strings.HasSuffix(name, "/")
}
