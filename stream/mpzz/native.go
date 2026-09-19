package mpzz

import (
	"encoding/binary"
	"fmt"
	"io"
)

type cachedHeaders struct {
	ident    []byte
	pages    []byte
	setup    vorbisSetup
	blocks   [2]int
	channels int
}

type oggreDecoder struct {
	r        io.Reader
	h        header
	cmd      *rangeDecoder
	control  [18]uint16
	previous uint32
	models   []integerModel
	probs    []uint16
	cache    bookCache
	headers  []cachedHeaders
	streams    [][]byte
	lastStream []byte
	dest       []byte
	lastOut    int
	lastPages  int
	lastLeft   int
	lastPath   string
	lastCached cachedHeaders
}

func newOGGREDecoder(r io.Reader, h header) (*oggreDecoder, error) {
	frame, err := readFrame(r)
	if err != nil {
		return nil, err
	}
	d := &oggreDecoder{r: r, h: h, cmd: newRange(frame), models: make([]integerModel, 55)}
	for i := range d.models {
		d.models[i].reset()
	}
	for i := range d.control {
		d.control[i] = 0x8000
	}
	d.cache.capacity = 1 << (4 + (h.flags & 7))
	d.probs = make([]uint16, 0x9225c+d.cache.capacity*0x45400)
	for i := range d.probs {
		d.probs[i] = 0x8000
	}
	return d, d.cmd.err
}

func (d *oggreDecoder) next() ([]byte, error) {
	d.previous = d.cmd.bit(&d.control[d.previous])
	if d.cmd.err != nil {
		return nil, d.cmd.err
	}
	if d.previous == 0 {
		b, err := readFrame(d.r)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, io.EOF
		}
		d.dest = append(d.dest, b...)
		d.lastStream = b
		d.lastPath = "raw"
		DebugPath = d.lastPath
		return b, nil
	}
	if d.cmd.bit(&d.control[2]) != 0 {
		back := int(d.models[52].integer(d.cmd, 5, 0, 2, true))
		n := len(d.streams)
		if n == 0 {
			return nil, fmt.Errorf("mpzz: stream cache empty")
		}
		index := n - 1 - back%n
		if index < 0 {
			index += n
		}
		// oggre_dec 0x401752: slot 3 serial integer on the command stream, then patch Ogg serial.
		serial := d.models[3].predict(d.models[3].integer(d.cmd, 5, 2, 4, false), 1)
		out, err := rewriteSerial(append([]byte(nil), d.streams[index]...), serial)
		if err != nil {
			return nil, err
		}
		d.lastStream = out
		d.dest = append(d.dest, out...)
		d.lastPath = fmt.Sprintf("replay back=%d idx=%d stored=%d ser=%d", back, index, len(d.streams), serial)
		DebugPath = d.lastPath
		return out, nil
	}
	store := d.cmd.bit(&d.control[6]) != 0
	var ranges [3]*rangeDecoder
	for i := range ranges {
		b, err := readFrame(d.r)
		if err != nil {
			return nil, err
		}
		DebugFrames[i] = len(b)
		ranges[i] = newRange(b)
	}
	if d.h.flags&8 != 0 {
		// Reset list at 0x10039006: probabilities persist in solid mode.
		for _, i := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23, 27, 28, 29, 30} {
			m := &d.models[i]
			m.value, m.delta, m.nonzero, m.sign, m.length = 0, 0, 0, 0, 0
		}
	} else {
		for i := 0; i < 52; i++ {
			d.models[i].reset()
		}
		for i := range d.probs {
			d.probs[i] = 0x8000
		}
		d.cache.books = nil
	}
	a := &audioDecoder{body: ranges[2], header: ranges[1], aux: ranges[0], models: d.models, probs: d.probs}
	for i := range d.cache.books {
		d.cache.books[i].used = false
	}
	out, err := d.decodeStream(a)
	if d.lastPath != "" {
		DebugPath = d.lastPath
	}
	if err != nil {
		return nil, err
	}
	d.lastStream = append([]byte(nil), out...)
	d.dest = append(d.dest, d.lastStream...)
	if store {
		d.streams = append(d.streams, d.lastStream)
	}
	if d.lastPath == "" {
		d.lastPath = fmt.Sprintf("decode store=%v headers=%d", store, len(d.headers))
	}
	DebugPath = d.lastPath
	for i := range d.cache.books {
		b := &d.cache.books[i]
		if !b.used && b.uses != 0 {
			b.uses--
		}
	}
	return out, nil
}

func rewriteSerial(pages []byte, serial uint32) ([]byte, error) {
	out := append([]byte(nil), pages...)
	for pos := 0; pos < len(out); {
		if len(out)-pos < 27 {
			return nil, fmt.Errorf("mpzz: truncated cached page")
		}
		n := int(out[pos+26])
		size := 27 + n
		if size > len(out)-pos {
			return nil, fmt.Errorf("mpzz: truncated cached lacing")
		}
		for _, v := range out[pos+27 : pos+size] {
			size += int(v)
		}
		if size > len(out)-pos {
			return nil, fmt.Errorf("mpzz: truncated cached body")
		}
		p := out[pos : pos+size]
		binary.LittleEndian.PutUint32(p[14:], serial)
		clear(p[22:26])
		binary.LittleEndian.PutUint32(p[22:], oggCRC(p))
		pos += size
	}
	return out, nil
}

func (d *oggreDecoder) decodeStream(a *audioDecoder) ([]byte, error) {
	h, err := decodePageHeader(a.header, d.models, &d.probs[0x208], 2, 0)
	if err != nil {
		return nil, fmt.Errorf("mpzz: identification streams=%d lastOut=%d lastPages=%d lastLeft=%d: %w", len(d.streams), d.lastOut, d.lastPages, d.lastLeft, err)
	}
	serial := h.serial
	DebugIdentN = len(h.packets)
	DebugSerial = serial
	last0 := 0
	if n := len(h.packets); n > 0 {
		last0 = h.packets[n-1]
	}
	identLike := len(h.packets) == 1 && h.packets[0] <= 32
	audioFirst := len(h.packets) == 1 && h.packets[0] > 32
	d.lastPath = fmt.Sprintf("ident n=%d ser=%08x flags=%02x last=%d identLike=%v audioFirst=%v", len(h.packets), serial, h.flags, last0, identLike, audioFirst)
	ident := setupDecoder{r: a.body, models: d.models, probs: d.probs}
	var out []byte
	if !audioFirst && len(h.packets) > 0 {
		ident.w.write(1, 8)
		for _, b := range []byte("vorbis") {
			ident.w.write(uint32(b), 8)
		}
		ident.w.write(0, 32)
		a.channels = int(ident.integer(9, 2, 1, 1, false, 1, 8))
		for i := 10; i < 14; i++ {
			ident.integer(i, 5, 1, 4, false, 1, 32)
		}
		block := ident.integer(14, 3, 1, 4, false, 1, 8)
		framing := ident.integer(15, 3, 1, 4, false, 1, 8)
		small, large := block&15, block>>4
		if a.channels < 1 || a.channels > 8 || small < 6 || large > 13 || small > large || framing&1 == 0 {
			return nil, fmt.Errorf("mpzz: invalid identification fields")
		}
		a.blocks = [2]int{1 << small, 1 << large}
		if h.packets[0] == len(ident.w.data) {
			out, err = h.marshal(ident.w.data)
		} else {
			identHdr := pageHeader{flags: 2, granule: h.granule, serial: h.serial, sequence: 0, packets: []int{len(ident.w.data)}, lacing: []byte{byte(len(ident.w.data))}}
			out, err = identHdr.marshal(ident.w.data)
		}
		if err != nil {
			return nil, err
		}
	}
	var config vorbisSetup
	if d.cmd.bit(&d.control[10]) != 0 {
		pages, cached, ent, err := d.applyCachedHeaders(serial)
		if err != nil {
			return nil, fmt.Errorf("mpzz: header cache after %s: %w", d.lastPath, err)
		}
		out = append(out, pages...)
		config = cached
		if a.channels == 0 && ent.channels != 0 {
			a.channels = ent.channels
			a.blocks = ent.blocks
		}
		// Empty body range: 02790 cannot run. PE 03690 extra_copy dest.
		if audioFirst {
			a.setup = &config
			d.lastPath += " first-audio"
			if len(a.body.data) <= 4 {
				d.lastPath += " destaudio"
				return d.decodeDestCopy(a, &h, out, serial)
			}
			data, err := d.decodeAudioPage(a, h, 0)
			if err != nil {
				return nil, err
			}
			out = append(out, data...)
			if h.flags&4 != 0 {
				return out, nil
			}
			return d.decodeAudioPages(a, out, 1)
		}
		if len(a.body.data) <= 4 {
			d.lastPath += " destaudio"
			a.setup = &config
			return d.decodeDestCopy(a, nil, out, serial)
		}
	} else {
		h, err = decodePageHeader(a.header, d.models, &d.probs[0x208], 0, 0)
		if err != nil {
			return nil, fmt.Errorf("mpzz: header page streams=%d: %w", len(d.streams), err)
		}
		if len(h.packets) != 2 {
			last := 0
			if n := len(h.packets); n > 0 {
				last = h.packets[n-1]
			}
			d.lastPath = fmt.Sprintf("destcopy identN=%d hdrN=%d lastLace=%d ser=%08x fl=%02x headers=%d", len(out), len(h.packets), last, h.serial, h.flags, len(d.headers))
			return d.decodeDestCopy(a, &h, out, serial)
		}
		comment := make([]byte, h.packets[0])
		prev := 0
		for i := range comment {
			comment[i] = byte(a.tree(a.body, 0x1218+(prev&0xf0)*16, 8))
			prev = int(comment[i])
		}
		s := setupDecoder{r: a.body, models: d.models, probs: d.probs, cache: &d.cache}
		books, err := s.codebooks()
		if err != nil {
			return nil, err
		}
		config, err = s.config(a.channels, books)
		if err != nil {
			return nil, err
		}
		a.w = s.w
		if err := a.finishPacket(h.packets[1]); err != nil {
			return nil, err
		}
		body := append(comment, a.w.data...)
		pages, err := h.marshal(body)
		if err != nil {
			return nil, err
		}
		out = append(out, pages...)
		stored := cachedHeaders{ident: append([]byte(nil), ident.w.data...), pages: pages, setup: config, blocks: a.blocks, channels: a.channels}
		d.lastCached = stored
		if d.cmd.bit(&d.control[14]) != 0 {
			d.headers = append(d.headers, stored)
			d.lastPath = fmt.Sprintf("newhdr store=1 identN=%d hdrN=%d headers=%d", len(out), len(h.packets), len(d.headers))
		} else {
			d.lastPath = fmt.Sprintf("newhdr store=0 identN=%d hdrN=%d", len(out), len(h.packets))
		}
	}
	a.setup = &config
	return d.decodeAudioPages(a, out, 0)
}

func (d *oggreDecoder) applyCachedHeaders(serial uint32) ([]byte, vorbisSetup, cachedHeaders, error) {
	if len(d.headers) == 0 {
		return nil, vorbisSetup{}, cachedHeaders{}, fmt.Errorf("mpzz: header cache empty")
	}
	back := int(d.models[53].integer(d.cmd, 5, 0, 2, true))
	n := len(d.headers)
	if n == 0 {
		return nil, vorbisSetup{}, cachedHeaders{}, fmt.Errorf("mpzz: header cache empty")
	}
	if back < 0 {
		back = -back
	}
	index := n - 1 - back%n
	d.lastPath = fmt.Sprintf("cache back=%d idx=%d headers=%d", back, index, n)
	cached := d.headers[index]
	d.lastCached = cached
	pages, err := rewriteSerial(cached.pages, serial)
	if err != nil {
		return nil, vorbisSetup{}, cachedHeaders{}, err
	}
	config := cached.setup
	config.books = append([]codebook(nil), config.books...)
	for i := range config.books {
		b := &config.books[i]
		if b.lookup != 0 {
			b.context = d.cache.selectBook(b, d.probs)
		}
	}
	d.models[37].value = d.models[29].value
	d.models[37].delta = 0
	return pages, config, cached, nil
}

func (d *oggreDecoder) decodeDestCopy(a *audioDecoder, first *pageHeader, out []byte, serial uint32) ([]byte, error) {
	src := d.lastStream
	if len(src) < 4 || string(src[:4]) != "OggS" {
		if n := len(d.streams); n > 0 {
			src = d.streams[n-1]
		} else {
			src = d.dest
		}
	}
	if len(src) == 0 {
		return nil, fmt.Errorf("mpzz: dest copy without prior stream")
	}
	// extra_copy_headers: comment+setup only. Ident was already emitted.
	_, headers, audio, err := splitDestPages(src)
	if err != nil {
		return nil, err
	}
	if first != nil {
		copied, err := rewriteSerial(headers, serial)
		if err != nil {
			return nil, err
		}
		out = append(out, copied...)
	}
	if len(audio) == 0 {
		return nil, fmt.Errorf("mpzz: dest copy has no audio")
	}
	off := 0
	take := func(h pageHeader) error {
		n := 0
		for _, v := range h.lacing {
			n += int(v)
		}
		body := make([]byte, n)
		for i := 0; i < n; i++ {
			body[i] = audio[(off+i)%len(audio)]
		}
		off += n
		page, err := h.marshal(body)
		if err != nil {
			return err
		}
		out = append(out, page...)
		return nil
	}
	page := 0
	if first != nil {
		if err := take(*first); err != nil {
			return nil, err
		}
		page = 1
	}
	// 03690 extra_copy: do not keep running 167c0. Copy remaining dest
	// audio pages whole so models 0-6 stay aligned for the next stream.
	pos := 0
	srcPages := src
	for pos+27 <= len(srcPages) {
		if string(srcPages[pos:pos+4]) != "OggS" {
			break
		}
		nseg := int(srcPages[pos+26])
		hsz := 27 + nseg
		if hsz > len(srcPages)-pos {
			break
		}
		body := 0
		for _, s := range srcPages[pos+27 : pos+hsz] {
			body += int(s)
		}
		size := hsz + body
		if size > len(srcPages)-pos {
			break
		}
		ptype := byte(0)
		if body > 0 {
			ptype = srcPages[pos+hsz]
		}
		if ptype != 1 && ptype != 3 && ptype != 5 {
			pageBytes := append([]byte(nil), srcPages[pos:pos+size]...)
			rewritten, err := rewriteSerial(pageBytes, serial)
			if err != nil {
				return nil, err
			}
			out = append(out, rewritten...)
			page++
		}
		pos += size
	}
	d.lastOut = len(out)
	d.lastPages = page
	d.lastLeft = len(a.header.data) - a.header.pos
	DebugDestPages = page
	DebugHeaderLeft = d.lastLeft
	return out, nil
}

func splitDestPages(dest []byte) (ident, headers, audio []byte, err error) {
	pos := 0
	for pos+27 <= len(dest) {
		if string(dest[pos:pos+4]) != "OggS" {
			return nil, nil, nil, fmt.Errorf("mpzz: dest page at %d not OggS", pos)
		}
		nseg := int(dest[pos+26])
		hsz := 27 + nseg
		if hsz > len(dest)-pos {
			return nil, nil, nil, fmt.Errorf("mpzz: dest lacing truncated")
		}
		body := 0
		for _, s := range dest[pos+27 : pos+hsz] {
			body += int(s)
		}
		size := hsz + body
		if size > len(dest)-pos {
			return nil, nil, nil, fmt.Errorf("mpzz: dest body truncated")
		}
		ptype := byte(0)
		if body > 0 {
			ptype = dest[pos+hsz]
		}
		switch ptype {
		case 1:
			ident = append(ident, dest[pos:pos+size]...)
		case 3, 5:
			headers = append(headers, dest[pos:pos+size]...)
		default:
			audio = append(audio, dest[pos+hsz:pos+size]...)
		}
		pos += size
	}
	return ident, headers, audio, nil
}

func (d *oggreDecoder) decodeAudioPages(a *audioDecoder, out []byte, page int) ([]byte, error) {
	for ; page < 1<<20; page++ {
		h, err := decodePageHeader(a.header, d.models, &d.probs[0x208], 0, a.granule)
		if err != nil {
			return nil, fmt.Errorf("mpzz: audio page %d streams=%d headers=%d: %w", page, len(d.streams), len(d.headers), err)
		}
		data, err := d.decodeAudioPage(a, h, page)
		if err != nil {
			return nil, err
		}
		out = append(out, data...)
		if h.flags&4 != 0 {
			d.lastOut = len(out)
			d.lastPages = page + 1
			d.lastLeft = len(a.header.data) - a.header.pos
			return out, nil
		}
	}
	return nil, fmt.Errorf("mpzz: excessive audio pages")
}

func (d *oggreDecoder) decodeAudioPage(a *audioDecoder, h pageHeader, page int) ([]byte, error) {
	// 02790 decodes one Vorbis packet; 03690 copies lace bytes into dest
	// and keeps leftover for a continued page (flags&1).
	var body []byte
	for i, size := range h.packets {
		for len(a.leftover) < size {
			mode, err := a.mode(h.flags)
			if err != nil {
				return nil, err
			}
			n := d.models[7].integer(a.aux, 3, 0, 1, true)
			if n != 0 {
				return nil, fmt.Errorf("mpzz: audio page %d packet %d has %d tail bits", page, i, n)
			}
			mapping := a.setup.mappings[mode.mapping]
			silent, err := a.floors(mapping)
			if err != nil {
				return nil, fmt.Errorf("mpzz: audio page %d packet %d floor: %w", page, i, err)
			}
			if err := a.residues(mapping, silent); err != nil {
				return nil, fmt.Errorf("mpzz: audio page %d packet %d residue: %w", page, i, err)
			}
			if len(a.w.data) <= size-len(a.leftover) {
				if err := a.finishPacket(size - len(a.leftover)); err != nil {
					return nil, fmt.Errorf("mpzz: audio page %d packet %d: %w", page, i, err)
				}
			}
			a.leftover = append(a.leftover, a.w.data...)
			if len(a.leftover) < size && len(a.w.data) == 0 {
				return nil, fmt.Errorf("mpzz: audio page %d packet %d needs %d have leftover %d", page, i, size, len(a.leftover))
			}
		}
		body = append(body, a.leftover[:size]...)
		a.leftover = a.leftover[size:]
	}
	return h.marshal(body)
}
