package garotafitness

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/lucasew/garotafitness/reconstruct/fgpack"
	"github.com/lucasew/garotafitness/reconstruct/i3d"
)

var errUnknownToolHash = errors.New("unknown tool hash")

type codec struct {
	id     string
	sha256 string
	names  []string
	encode func(ctx context.Context, in []byte, args []string) ([]byte, error)
}

// toolset indexes reconstruct PEs by content hash. The same binary reuses
// one codec even when a torrent ships it under a different exe name.
type toolset struct {
	byHash map[string]codec
	byName map[string][]codec
}

func newToolset() *toolset {
	s := &toolset{byHash: map[string]codec{}, byName: map[string][]codec{}}
	lzma := func(ctx context.Context, in []byte, args []string) ([]byte, error) {
		o, _, _, err := packingOptions(args)
		if err != nil {
			return nil, err
		}
		return fgpack.EncodeWithOptions(ctx, in, o)
	}
	i3dEnc := func(_ context.Context, in []byte, _ []string) ([]byte, error) {
		return i3d.Apply(in)
	}
	s.add(codec{id: "lzma", sha256: "a95222984f60e3f5bea4099cab85868946523391b0e50d7f6dcc5e866d0b0dbd", names: []string{"fgpack.exe"}, encode: lzma})
	s.add(codec{id: "lzma", names: []string{"fgpack.exe"}, encode: lzma})
	s.add(codec{id: "i3d", sha256: "eb9a914ff781bc2f088e70d1b99faca73d98a96325a4a154cf52b3b52a4f860a", names: []string{"fgpack.exe"}, encode: i3dEnc})
	s.add(codec{id: "xdelta", sha256: "09763ca90c09a5f815a94527399b1f2a88685e9de462e2ff1bc5648d320e707a", names: []string{"x.exe", "xdelta.exe", "xdelta3.exe"}})
	s.add(codec{id: "x2", sha256: "985f5ff185749eba4cf6d0ddf3458762667266be3838a10c4c1dfbb9ce91d8ea", names: []string{"x2.exe"}})
	s.add(codec{id: "x3", sha256: "6484a5f0d82087f4c31218fc7e96c09abef6ff38cf0879ccd070fab947dc3573", names: []string{"x3.exe"}})
	s.add(codec{id: "defarm", sha256: "7889aadec74fe2e4940a3dab081b8d560d7d751b0ed13cfc90b8986ca6ae084f", names: []string{"x4.exe"}})
	s.add(codec{id: "x5", sha256: "342b579afeff5651e9c0c57a6d2e785f119655f170d106dd01dfb97162efe385", names: []string{"x5.exe"}})
	s.add(codec{id: "x5n", sha256: "234168f765294a5db867163e639c9288f04f976976bdf80da29fbba9eae39917", names: []string{"x5n.exe"}})
	s.add(codec{id: "fsb", sha256: "98d7c11a27dc7b0da976d5b01374e0359d92b2d3b5439c5d26bad70ec618d811", names: []string{"fsb.exe"}})
	s.add(codec{id: "7z", sha256: "bfb34635f295df13ea1677c0d51d08fafd2da21a1c0bea252df6342d40e511a0", names: []string{"7z.exe"}})
	s.add(codec{id: "fart", sha256: "c9ef35bed70ffa0981bafd0071185b56fdad8f9c97f3582a4dae9b420959fb97", names: []string{"fart.exe"}})
	s.add(codec{id: "run", sha256: "3243562d5d0685b57bc237b24f254d1d18d6abcb1f8ddac2698c2d9208c76247", names: []string{"run.exe"}})
	s.add(codec{id: "countdown", sha256: "3ebdeea17770bd829046903c58b4815e0efd952518b287c441166247def0b64c", names: []string{"countdown.exe"}})
	s.add(codec{id: "oggre", sha256: "bd21153f84d1bc74dc2771baf4e91ebfe0c46df50e4ad79f8429a88784ced3cb", names: []string{"oggre_dec.exe"}})
	s.add(codec{id: "xtool", sha256: "a1c80a60363e23d475e8ef6eeaec373c6529d6974f4f463d5a4cb4eae484a07c", names: []string{"xtool.exe"}})
	s.add(codec{id: "xtool", sha256: "4e8d72aa273434767dc2ae3190758efe37d42c44c980a1ec76e97de08e4b7aa7", names: []string{"xtool.exe"}})
	return s
}

func (s *toolset) add(c codec) {
	c.sha256 = strings.ToLower(c.sha256)
	if c.sha256 != "" {
		s.byHash[c.sha256] = c
	}
	for _, n := range c.names {
		n = strings.ToLower(n)
		s.byName[n] = append(s.byName[n], c)
	}
}

var reconstructToolset = newToolset()

func (s *toolset) match(name, digest string) (codec, error) {
	name = strings.ToLower(name)
	digest = strings.ToLower(digest)
	if digest != "" {
		if c, ok := s.byHash[digest]; ok {
			return c, nil
		}
		if len(s.byName[name]) > 0 {
			return codec{}, fmt.Errorf("%s sha256:%s: %w", name, digest, errUnknownToolHash)
		}
		return codec{}, fmt.Errorf("unknown reconstruct tool %s sha256:%s", name, digest)
	}
	list := s.byName[name]
	if len(list) == 0 {
		return codec{}, fmt.Errorf("unknown reconstruct tool %s", name)
	}
	var named []codec
	for _, c := range list {
		if c.sha256 == "" {
			named = append(named, c)
		}
	}
	switch {
	case len(named) == 1:
		return named[0], nil
	case len(list) == 1:
		return list[0], nil
	default:
		return codec{}, fmt.Errorf("reconstruct tool %s: missing binary hash", name)
	}
}

func (s *toolset) canonical(name, digest string) string {
	c, err := s.match(name, digest)
	if err != nil || len(c.names) == 0 {
		return name
	}
	return strings.ToLower(c.names[0])
}

func (s *toolset) run(ctx context.Context, name, digest string, in []byte, args []string, wantMD5 []byte) ([]byte, error) {
	c, err := s.match(name, digest)
	switch {
	case err == nil:
		if c.encode == nil {
			return nil, fmt.Errorf("reconstruct tool %s: no encoder", c.id)
		}
		return c.encode(ctx, in, args)
	case errors.Is(err, errUnknownToolHash) && len(wantMD5) > 0:
		return s.runByChecksum(ctx, name, in, args, wantMD5)
	default:
		return nil, err
	}
}

func (s *toolset) runByChecksum(ctx context.Context, name string, in []byte, args []string, wantMD5 []byte) ([]byte, error) {
	var win []byte
	var n int
	seen := map[string]bool{}
	for _, c := range s.byName[strings.ToLower(name)] {
		if c.sha256 == "" || c.encode == nil || seen[c.sha256] {
			continue
		}
		seen[c.sha256] = true
		out, err := c.encode(ctx, in, args)
		if err != nil {
			continue
		}
		sum := md5.Sum(out)
		if !bytes.Equal(sum[:], wantMD5) {
			continue
		}
		n++
		win = out
	}
	if n == 0 {
		return nil, fmt.Errorf("reconstruct: no codec matched checksum")
	}
	if n > 1 {
		return nil, fmt.Errorf("reconstruct: multiple codecs matched checksum")
	}
	return win, nil
}

func (p *reconstructionPlan) fileChecksum(rel string) []byte {
	if p == nil || p.want == nil {
		return nil
	}
	rel = strings.ReplaceAll(rel, "\\", "/")
	for _, key := range []string{rel, strings.TrimPrefix(rel, "app/")} {
		if b := p.want[key]; len(b) > 0 {
			return b
		}
	}
	return nil
}

func (p *reconstructionPlan) toolDigest(program, cwd string) string {
	n, err := virtualPath(program, cwd)
	if err != nil {
		return ""
	}
	b, err := p.read(n)
	if err != nil || len(b) == 0 {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
