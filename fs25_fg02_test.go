package garotafitness

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"testing"

	"github.com/lewtec/lewkit/x/test"
	"github.com/lucasew/garotafitness/internal/corpus"
	"github.com/lucasew/garotafitness/stream/mpzz"
	"github.com/stretchr/testify/require"
)

func TestDumpFS25Fg02MpzzHead(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	vol, err := src.Open("fg-02.bin")
	require.NoError(t, err)
	test.CloseOnCleanup(t, vol)
	st, err := vol.Stat()
	require.NoError(t, err)
	ra := vol.(interface {
		ReadAt([]byte, int64) (int, error)
	})
	v, err := parseVolumeAt("fg-02.bin", ra, st.Size())
	require.NoError(t, err)
	var s *solid
	for g := range groupSolids(v.Members) {
		cp := g
		s = &cp
		break
	}
	require.NotNil(t, s)
	t.Logf("pipe=%s", s.pipe)

	// Decode outer 4x4:tor and srep only. Leave 4x4:mpzz blocks intact.
	var r io.Reader = io.NewSectionReader(ra, s.off, int64(s.csz))
	for i := len(s.pipe) - 1; i >= 1; i-- {
		dec, err := Decode(t.Context(), r, s.pipe[i])
		require.NoError(t, err, s.pipe[i])
		test.CloseOnCleanup(t, dec)
		r = dec
	}
	head := make([]byte, 64)
	n, err := io.ReadFull(r, head)
	require.NoError(t, err)
	t.Logf("read %d after %s\n%s", n, s.pipe[1:], hex.Dump(head))
}

func TestFS25Fg02FirstMpzzBlock(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	vol, err := src.Open("fg-02.bin")
	require.NoError(t, err)
	test.CloseOnCleanup(t, vol)
	st, err := vol.Stat()
	require.NoError(t, err)
	ra := vol.(interface {
		ReadAt([]byte, int64) (int, error)
	})
	v, err := parseVolumeAt("fg-02.bin", ra, st.Size())
	require.NoError(t, err)
	var s *solid
	for g := range groupSolids(v.Members) {
		cp := g
		s = &cp
		break
	}
	require.NotNil(t, s)

	var r io.Reader = io.NewSectionReader(ra, s.off, int64(s.csz))
	for i := len(s.pipe) - 1; i >= 1; i-- {
		dec, err := Decode(t.Context(), r, s.pipe[i])
		require.NoError(t, err, s.pipe[i])
		test.CloseOnCleanup(t, dec)
		r = dec
	}

	var ver [4]byte
	_, err = io.ReadFull(r, ver[:])
	require.NoError(t, err)
	var hdr [8]byte
	_, err = io.ReadFull(r, hdr[:])
	require.NoError(t, err)
	outSize := uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16 | uint32(hdr[3])<<24
	inSize := uint32(hdr[4]) | uint32(hdr[5])<<8 | uint32(hdr[6])<<16 | uint32(hdr[7])<<24
	t.Logf("ver=%x out=%d in=%d", ver, outSize, inSize)
	in := make([]byte, inSize)
	_, err = io.ReadFull(r, in)
	require.NoError(t, err)
	t.Logf("block0 head %q flags=%02x", in[:7], in[6])
	require.NoError(t, os.WriteFile("/tmp/fs25-fg02-block0.oggre", in, 0644))
	t.Logf("wrote /tmp/fs25-fg02-block0.oggre %d", len(in))
	gotGuest, err := mpzz.DecodeGuest(t.Context(), in, 256<<20)
	if err != nil {
		t.Logf("guest: %v", err)
	} else {
		t.Logf("guest n=%d head=%q", len(gotGuest), gotGuest[:min(16, len(gotGuest))])
	}

	dec, err := Decode(t.Context(), bytes.NewReader(in), Atom{Algo: AlgoMPZZ})
	require.NoError(t, err)
	test.CloseOnCleanup(t, dec)
	got := make([]byte, 64)
	n, err := io.ReadFull(dec, got)
	t.Logf("mpzz first %d %v\n%s", n, err, hex.Dump(got[:max(0, n)]))
	require.NoError(t, err)
}

func TestFS25Fg02FirstBlockFull(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	vol, err := src.Open("fg-02.bin")
	require.NoError(t, err)
	test.CloseOnCleanup(t, vol)
	st, err := vol.Stat()
	require.NoError(t, err)
	ra := vol.(interface {
		ReadAt([]byte, int64) (int, error)
	})
	v, err := parseVolumeAt("fg-02.bin", ra, st.Size())
	require.NoError(t, err)
	var s *solid
	for g := range groupSolids(v.Members) {
		cp := g
		s = &cp
		break
	}
	require.NotNil(t, s)
	var r io.Reader = io.NewSectionReader(ra, s.off, int64(s.csz))
	for i := len(s.pipe) - 1; i >= 1; i-- {
		dec, err := Decode(t.Context(), r, s.pipe[i])
		require.NoError(t, err, s.pipe[i])
		test.CloseOnCleanup(t, dec)
		r = dec
	}
	var ver [4]byte
	_, err = io.ReadFull(r, ver[:])
	require.NoError(t, err)
	var hdr [8]byte
	_, err = io.ReadFull(r, hdr[:])
	require.NoError(t, err)
	outSize := uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16 | uint32(hdr[3])<<24
	inSize := uint32(hdr[4]) | uint32(hdr[5])<<8 | uint32(hdr[6])<<16 | uint32(hdr[7])<<24
	in := make([]byte, inSize)
	_, err = io.ReadFull(r, in)
	require.NoError(t, err)
	dec, err := Decode(t.Context(), bytes.NewReader(in), Atom{Algo: AlgoMPZZ})
	require.NoError(t, err)
	test.CloseOnCleanup(t, dec)
	n, err := io.Copy(io.Discard, dec)
	require.NoError(t, err)
	t.Logf("block0 out=%d want=%d", n, outSize)
	require.Equal(t, int64(outSize), n)
}

func TestFS25Fg02FirstStreamPages(t *testing.T) {
	src := corpus.OpenEnv(t, fs25Corpus)
	vol, err := src.Open("fg-02.bin")
	require.NoError(t, err)
	test.CloseOnCleanup(t, vol)
	st, err := vol.Stat()
	require.NoError(t, err)
	ra := vol.(interface {
		ReadAt([]byte, int64) (int, error)
	})
	v, err := parseVolumeAt("fg-02.bin", ra, st.Size())
	require.NoError(t, err)
	var s *solid
	for g := range groupSolids(v.Members) {
		cp := g
		s = &cp
		break
	}
	var r io.Reader = io.NewSectionReader(ra, s.off, int64(s.csz))
	for i := len(s.pipe) - 1; i >= 1; i-- {
		dec, err := Decode(t.Context(), r, s.pipe[i])
		require.NoError(t, err, s.pipe[i])
		test.CloseOnCleanup(t, dec)
		r = dec
	}
	var ver [4]byte
	_, err = io.ReadFull(r, ver[:])
	require.NoError(t, err)
	var hdr [8]byte
	_, err = io.ReadFull(r, hdr[:])
	require.NoError(t, err)
	inSize := uint32(hdr[4]) | uint32(hdr[5])<<8 | uint32(hdr[6])<<16 | uint32(hdr[7])<<24
	in := make([]byte, inSize)
	_, err = io.ReadFull(r, in)
	require.NoError(t, err)
	dec, err := Decode(t.Context(), bytes.NewReader(in), Atom{Algo: AlgoMPZZ})
	require.NoError(t, err)
	test.CloseOnCleanup(t, dec)
	// One Read pulls one OGGRE record (next()).
	buf := make([]byte, 1<<20)
	n, err := dec.Read(buf)
	require.NoError(t, err)
	got := append([]byte(nil), buf[:n]...)
	t.Logf("record0 n=%d crc=%08x path=%s head=%q", n, crc32.ChecksumIEEE(got), mpzz.DebugPath, got[:min(8, n)])
	pos := 0
	for i := 0; pos+27 <= len(got); i++ {
		require.Equal(t, "OggS", string(got[pos:pos+4]), "page %d at %d", i, pos)
		flags := got[pos+5]
		serial := uint32(got[pos+14]) | uint32(got[pos+15])<<8 | uint32(got[pos+16])<<16 | uint32(got[pos+17])<<24
		nseg := int(got[pos+26])
		size := 27 + nseg
		body := 0
		for _, s := range got[pos+27 : pos+27+nseg] {
			body += int(s)
			size += int(s)
		}
		t.Logf("page %d off=%d flags=%02x segs=%d body=%d size=%d serial=%08x lastLace=%d", i, pos, flags, nseg, body, size, serial, got[pos+26+nseg])
		pos += size
	}
	t.Logf("tail=%d", len(got)-pos)
	total := n
	for rec := 1; rec < 256; rec++ {
		n2, err := dec.Read(buf)
		total += n2
		if n2 > 0 {
			chunk := buf[:n2]
			serial := uint32(0)
			if n2 >= 18 {
				serial = uint32(chunk[14]) | uint32(chunk[15])<<8 | uint32(chunk[16])<<16 | uint32(chunk[17])<<24
			}
			same0 := n2 == len(got) && string(chunk) == string(got)
			t.Logf("record%d n=%d crc=%08x serial=%08x same0=%v path=%s identN=%d idSer=%08x destPages=%d hdrLeft=%d frames=%v err=%v total=%d", rec, n2, crc32.ChecksumIEEE(chunk), serial, same0, mpzz.DebugPath, mpzz.DebugIdentN, mpzz.DebugSerial, mpzz.DebugDestPages, mpzz.DebugHeaderLeft, mpzz.DebugFrames, err, total)
		} else {
			t.Logf("record%d n=%d path=%s identN=%d idSer=%08x destPages=%d hdrLeft=%d frames=%v err=%v total=%d", rec, n2, mpzz.DebugPath, mpzz.DebugIdentN, mpzz.DebugSerial, mpzz.DebugDestPages, mpzz.DebugHeaderLeft, mpzz.DebugFrames, err, total)
		}
		if err != nil {
			break
		}
	}
}

func TestFS25Fg02DumpAllMpzzBlocks(t *testing.T) {
	skipHeavySolid(t)
	src := corpus.OpenEnv(t, fs25Corpus)
	vol, err := src.Open("fg-02.bin")
	require.NoError(t, err)
	test.CloseOnCleanup(t, vol)
	st, err := vol.Stat()
	require.NoError(t, err)
	ra := vol.(interface {
		ReadAt([]byte, int64) (int, error)
	})
	v, err := parseVolumeAt("fg-02.bin", ra, st.Size())
	require.NoError(t, err)
	var s *solid
	for g := range groupSolids(v.Members) {
		cp := g
		s = &cp
		break
	}
	require.NotNil(t, s)
	var r io.Reader = io.NewSectionReader(ra, s.off, int64(s.csz))
	for i := len(s.pipe) - 1; i >= 1; i-- {
		dec, err := Decode(t.Context(), r, s.pipe[i])
		require.NoError(t, err, s.pipe[i])
		test.CloseOnCleanup(t, dec)
		r = dec
	}
	var ver [4]byte
	_, err = io.ReadFull(r, ver[:])
	require.NoError(t, err)
	require.Equal(t, uint32(0), binary.LittleEndian.Uint32(ver[:]))
	for n := 0; ; n++ {
		var hdr [8]byte
		k, err := io.ReadFull(r, hdr[:])
		if k == 0 && (err == io.EOF || err == io.ErrUnexpectedEOF) {
			t.Logf("blocks=%d", n)
			return
		}
		require.NoError(t, err)
		outSize := binary.LittleEndian.Uint32(hdr[0:4])
		inSize := binary.LittleEndian.Uint32(hdr[4:8])
		in := make([]byte, inSize)
		_, err = io.ReadFull(r, in)
		require.NoError(t, err, "block %d", n)
		path := fmt.Sprintf("/tmp/fs25-fg02-block%d.oggre", n)
		require.NoError(t, os.WriteFile(path, in, 0644))
		t.Logf("block %d in=%d out=%d mag=%q flags=%02x -> %s", n, inSize, outSize, in[:min(5, len(in))], in[6], path)
	}
}
