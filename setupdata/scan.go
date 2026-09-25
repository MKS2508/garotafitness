// Package setupdata reads setup.exe as data (TEC-04, ADR-0003).
// Volume headers stay the primary Encoder names.
package setupdata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	ulzma "github.com/ulikunitz/xz/lzma"
)

// Info is Encoder names and arc.ini text collected from setup.exe.
type Info struct {
	Encoders     []string    // unique method/encoder tokens found
	ArcINI       string      // arc.ini (or equivalent) text if present
	InstalledMD5 string      // contiguous installed-file manifest, relative to ManifestPath's directory
	Operations   []Operation // reconstruction records recovered from compiled setup metadata
	ManifestPath string      // {app}-relative checksum destination from Inno file metadata
}

const (
	zlbMagic     = "zlb\x1a"
	innoDataID   = "Inno Setup Setup Data ("
	innoIDLen    = 64
	chunkCRCSize = 4096
	maxStored    = 16 << 20
	maxPlain     = 32 << 20
	maxDict      = 128 << 20
)

// known is the FreeArc / FitGirl atom set this repo already names.
// Longer aliases are listed so a scan can match them as whole tokens.
var known = []string{
	"dispack070",
	"fgpack2",
	"magic2l",
	"dispack",
	"storing",
	"fgpack",
	"magic2",
	"xt2png",
	"xt3u",
	"lzma2",
	"ppmd",
	"pref",
	"srep",
	"mpzz",
	"rzwb",
	"rzs",
	"lzma",
	"delta",
	"4x4",
	"rzw",
	"mpz",
	"rep",
	"x2",
	"x3",
	"x5",
}

var errNil = errors.New("setupdata: nil reader")

// Scan reads setup.exe bytes. It never maps them as executable.
func Scan(r io.Reader) (Info, error) {
	if r == nil {
		return Info{}, errNil
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return Info{}, err
	}
	var hay [][]byte
	hay = append(hay, data)
	hay = append(hay, decompressHeaders(data)...)
	hay = append(hay, decompressZLB(data)...)

	var u uniq
	var arc string
	var manifest string
	var operations []Operation
	var manifestPath string
	for _, h := range hay {
		if candidate := installedManifestPath(h); candidate != "" {
			manifestPath = candidate
		}
		if arc == "" {
			arc = extractArcINI(h)
		}
		collectKnown(&u, h)
		if candidate := installedMD5(h); len(candidate) > len(manifest) {
			manifest = candidate
		}
		if i := bytes.Index(h, []byte("IFPS")); i >= 0 {
			plan, err := reconstructionPlan(h[i:])
			if err != nil {
				return Info{}, err
			}
			if len(plan) > len(operations) {
				operations = plan
			}
		}
	}
	collectINI(&u, arc)
	return Info{Encoders: u.list, ArcINI: arc, InstalledMD5: manifest, Operations: operations, ManifestPath: manifestPath}, nil
}

// The Inno payload includes the manifest as plain text. Require complete,
// consecutive MD5 lines; paths are relative to its metadata destination.
var installedMD5Lines = regexp.MustCompile(`(?m)(?:[0-9a-fA-F]{32} [ *][^\x00\r\n]+\r?\n)+`)

func installedMD5(data []byte) string {
	var best []byte
	for _, b := range installedMD5Lines.FindAll(data, -1) {
		if len(b) > len(best) {
			best = b
		}
	}
	if utf8.Valid(best) {
		return string(best)
	}
	var out strings.Builder
	for _, c := range best {
		if c < 128 {
			out.WriteByte(c)
		} else {
			out.WriteRune(cp1251[c-128])
		}
	}
	return out.String()
}

type uniq struct {
	list []string
	seen map[string]struct{}
}

func (u *uniq) add(s string) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return
	}
	if u.seen == nil {
		u.seen = make(map[string]struct{})
	}
	if _, ok := u.seen[s]; ok {
		return
	}
	u.seen[s] = struct{}{}
	u.list = append(u.list, s)
}

func collectKnown(u *uniq, hay []byte) {
	lower := bytes.ToLower(hay)
	for _, tok := range known {
		if hasToken(lower, []byte(tok)) || hasTokenUTF16(hay, tok) {
			u.add(tok)
		}
	}
}

func collectINI(u *uniq, arc string) {
	if arc == "" {
		return
	}
	for _, line := range strings.Split(arc, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
			continue
		}
		sec := line[1 : len(line)-1]
		name, rest, ok := strings.Cut(sec, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "External compressor") {
			for _, part := range strings.Split(rest, ",") {
				u.add(part)
			}
			continue
		}
		if isTokenName(sec) {
			u.add(sec)
		}
	}
}

func isTokenName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 && !unicode.IsLetter(r) {
			return false
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func hasToken(hay, tok []byte) bool {
	if len(tok) == 0 {
		return false
	}
	start := 0
	for {
		i := bytes.Index(hay[start:], tok)
		if i < 0 {
			return false
		}
		i += start
		if tokenBound(hay, i, i+len(tok)) {
			return true
		}
		start = i + 1
	}
}

func hasTokenUTF16(hay []byte, tok string) bool {
	enc := utf16LE(strings.ToLower(tok))
	up := utf16LE(strings.ToUpper(tok))
	return hasUTF16At(hay, enc) || hasUTF16At(hay, up)
}

func hasUTF16At(hay, tok []byte) bool {
	start := 0
	for {
		i := bytes.Index(hay[start:], tok)
		if i < 0 {
			return false
		}
		i += start
		if utf16Bound(hay, i, i+len(tok)) {
			return true
		}
		start = i + 2
	}
}

func tokenBound(b []byte, i, j int) bool {
	if i > 0 && isWord(b[i-1]) {
		return false
	}
	if j < len(b) && isWord(b[j]) {
		return false
	}
	return true
}

func utf16Bound(b []byte, i, j int) bool {
	if i >= 2 && b[i-1] == 0 && isWord(b[i-2]) {
		return false
	}
	if j+1 < len(b) && b[j+1] == 0 && isWord(b[j]) {
		return false
	}
	return true
}

func isWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return out
}

func extractArcINI(b []byte) string {
	key := []byte("[External compressor:")
	var best []byte
	for i := 0; i < len(b); {
		j := bytes.Index(b[i:], key)
		if j < 0 {
			break
		}
		j += i
		rest := b[j+len(key):]
		k := bytes.IndexByte(rest, ']')
		if k < 0 || k > 120 || !iniNameList(rest[:k]) {
			i = j + 1
			continue
		}
		after := rest[k+1:]
		if len(after) == 0 || after[0] != '\r' && after[0] != '\n' {
			i = j + 1
			continue
		}
		end := j
		for end < len(b) && isINIByte(b[end]) {
			end++
		}
		cand := b[j:end]
		if iniScore(cand) > iniScore(best) {
			best = cand
		}
		i = j + 1
	}
	if len(best) == 0 {
		return ""
	}
	if !bytes.HasSuffix(best, []byte("\n")) && !bytes.HasSuffix(best, []byte("\r")) {
		if n := bytes.LastIndexAny(best, "\r\n"); n >= 0 {
			best = best[:n+1]
		}
	}
	return string(best)
}

func iniNameList(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		switch {
		case isWord(c), c == ',', c == ' ', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func isINIByte(c byte) bool {
	return c == '\t' || c == '\n' || c == '\r' || c >= 32 && c < 127
}

func iniScore(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	n := len(b)
	if bytes.Contains(b, []byte("\r\n")) {
		n += 1 << 20
	}
	return n
}

func decompressHeaders(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for {
		i := bytes.Index(data[start:], []byte(innoDataID))
		if i < 0 {
			return out
		}
		i += start
		if i+innoIDLen > len(data) {
			start = i + 1
			continue
		}
		pos := i + innoIDLen
		for n := 0; n < 2; n++ {
			plain, next, ok := readInnoBlock(data, pos)
			if !ok {
				break
			}
			out = append(out, plain)
			pos = next
		}
		start = i + 1
	}
}

func readInnoBlock(data []byte, pos int) ([]byte, int, bool) {
	if pos+9 > len(data) {
		return nil, pos, false
	}
	want := binary.LittleEndian.Uint32(data[pos:])
	stored := binary.LittleEndian.Uint32(data[pos+4:])
	if crc32.ChecksumIEEE(data[pos+4:pos+9]) != want {
		return nil, pos, false
	}
	if stored == 0 || stored > maxStored || pos+9+int(stored) > len(data) {
		return nil, pos, false
	}
	next := pos + 9 + int(stored)
	raw := stripChunkCRC(data[pos+9 : next])
	if data[pos+8] == 0 {
		return raw, next, true
	}
	plain, err := decodeLZMA1(raw)
	if err != nil {
		return nil, pos, false
	}
	return plain, next, true
}

func stripChunkCRC(stored []byte) []byte {
	out := make([]byte, 0, len(stored))
	for len(stored) >= 4 {
		stored = stored[4:]
		n := chunkCRCSize
		if n > len(stored) {
			n = len(stored)
		}
		out = append(out, stored[:n]...)
		stored = stored[n:]
	}
	return out
}

func decodeLZMA1(payload []byte) ([]byte, error) {
	if len(payload) < 5 {
		return nil, io.ErrUnexpectedEOF
	}
	dict := binary.LittleEndian.Uint32(payload[1:5])
	if dict == 0 || int(dict) > maxDict {
		return nil, errors.New("setupdata: lzma1 dict")
	}
	hdr := make([]byte, 13)
	copy(hdr[:5], payload[:5])
	for i := 5; i < 13; i++ {
		hdr[i] = 0xff
	}
	r, err := ulzma.ReaderConfig{DictCap: int(dict)}.NewReader(
		io.MultiReader(bytes.NewReader(hdr), bytes.NewReader(payload[5:])),
	)
	if err != nil {
		return nil, err
	}
	return readCap(r, maxPlain)
}

func decompressZLB(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for {
		i := bytes.Index(data[start:], []byte(zlbMagic))
		if i < 0 {
			return out
		}
		i += start
		payload := data[i+len(zlbMagic):]
		if plain, err := decodeLZMA2(payload); err == nil && len(plain) > 0 {
			out = append(out, plain)
		}
		start = i + 1
	}
}

func decodeLZMA2(payload []byte) ([]byte, error) {
	if len(payload) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	dict := lzma2Dict(payload[0])
	if dict <= 0 || dict > maxDict {
		return nil, errors.New("setupdata: lzma2 dict")
	}
	r, err := ulzma.Reader2Config{DictCap: dict}.NewReader2(bytes.NewReader(payload[1:]))
	if err != nil {
		return nil, err
	}
	return readCap(r, maxPlain)
}

func lzma2Dict(prop byte) int {
	if prop > 40 {
		return 0
	}
	if prop == 40 {
		return maxDict
	}
	return (2 | int(prop&1)) << (int(prop)/2 + 11)
}

func readCap(r io.Reader, capn int) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, int64(capn)))
}
