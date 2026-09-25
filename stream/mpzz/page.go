package mpzz

import (
	"encoding/binary"
	"fmt"
)

type pageHeader struct {
	flags            byte
	granule          uint64
	serial, sequence uint32
	packets          []int
	lacing           []byte
}

func oggCRC(data []byte) uint32 {
	var crc uint32
	for _, b := range data {
		crc ^= uint32(b) << 24
		for range 8 {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ 0x04c11db7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func (h pageHeader) marshal(body []byte) ([]byte, error) {
	size := 0
	for _, n := range h.lacing {
		size += int(n)
	}
	if size != len(body) {
		return nil, fmt.Errorf("mpzz: page body %d != lacing %d", len(body), size)
	}
	if len(h.lacing) <= 255 {
		return h.emit(h.flags, h.sequence, h.lacing, body)
	}
	// Official 167c0 / emit_page_pkts: flush an Ogg page at 255 laces.
	return h.marshalSplit(body)
}

func (h pageHeader) emit(flags byte, seq uint32, lacing, body []byte) ([]byte, error) {
	if len(lacing) > 255 {
		return nil, fmt.Errorf("mpzz: emit lacing %d", len(lacing))
	}
	p := make([]byte, 27+len(lacing), 27+len(lacing)+len(body))
	copy(p, "OggS")
	p[5] = flags
	binary.LittleEndian.PutUint64(p[6:], h.granule)
	binary.LittleEndian.PutUint32(p[14:], h.serial)
	binary.LittleEndian.PutUint32(p[18:], seq)
	p[26] = byte(len(lacing))
	copy(p[27:], lacing)
	p = append(p, body...)
	binary.LittleEndian.PutUint32(p[22:], oggCRC(p))
	return p, nil
}

func (h pageHeader) marshalSplit(body []byte) ([]byte, error) {
	var out []byte
	seq := h.sequence
	flags := h.flags
	li, boff := 0, 0
	var segs []byte
	pay := 0
	flush := func(last bool) error {
		f := flags &^ 4
		if last {
			f = flags
		}
		page, err := h.emit(f, seq, segs, body[boff:boff+pay])
		if err != nil {
			return err
		}
		out = append(out, page...)
		if len(segs) > 0 && segs[len(segs)-1] == 255 {
			flags = flags&^2 | 1
		} else {
			flags = flags &^ 3
		}
		seq++
		boff += pay
		segs = segs[:0]
		pay = 0
		return nil
	}
	for i, sl := range h.packets {
		start := li
		if sl == 0 {
			li++
		} else {
			for sl > 0 && li < len(h.lacing) {
				sl -= int(h.lacing[li])
				li++
			}
			if i == len(h.packets)-1 && li < len(h.lacing) {
				li++
			}
		}
		for start < li {
			take := li - start
			room := 255 - len(segs)
			if room == 0 {
				if err := flush(false); err != nil {
					return nil, err
				}
				room = 255
			}
			if take > room {
				take = room
			}
			chunk := h.lacing[start : start+take]
			segs = append(segs, chunk...)
			for _, v := range chunk {
				pay += int(v)
			}
			start += take
		}
	}
	if err := flush(true); err != nil {
		return nil, err
	}
	return out, nil
}

// 0x100167c0: the page stream carries packet lengths rather than the
// expanded Ogg lacing table. granuleBase comes from decoded audio blocks.
func decodePageHeader(r *rangeDecoder, models []integerModel, terminal *uint16, flags byte, granuleBase uint32) (pageHeader, error) {
	h := pageHeader{}
	h.flags = byte(models[0].integer(r, 3, 0, 2, false)) ^ flags
	lo := models[1].predict(models[1].integer(r, 5, 2, 4, false), 1) + granuleBase
	hi := models[2].predict(models[2].integer(r, 5, 1, 1, false), 1)
	h.granule = uint64(hi)<<32 | uint64(lo)
	h.serial = models[3].predict(models[3].integer(r, 5, 2, 4, false), 1)
	h.sequence = models[4].predict(models[4].integer(r, 5, 2, 4, false), 2)
	n := models[5].integer(r, 3, 0, 4, true)
	if n > 255 {
		return h, fmt.Errorf("mpzz: page has %d packets", n)
	}
	for i := uint32(0); i < n; i++ {
		size := models[6].integer(r, 4, 0, 6, true)
		if size > 16<<20 {
			return h, fmt.Errorf("mpzz: packet fragment exceeds page capacity: %d (n=%d i=%d lacing=%d)", size, n, i, len(h.lacing))
		}
		h.packets = append(h.packets, int(size))
		for size >= 255 {
			h.lacing = append(h.lacing, 255)
			size -= 255
		}
		if size != 0 || i+1 < n || r.bit(terminal) != 0 {
			h.lacing = append(h.lacing, byte(size))
		}
	}
	return h, r.err
}
