package rzw

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// The auxiliary streams use a single FSM per binary decision, rather than
// the pair of states mixed by the LZ kernel. Reference: 0x428110, 0x4183f0.
var stateFreq = func() [256]uint32 {
	var p [256]uint32
	q := uint32(0x80000000)
	p[128] = q >> 20
	for i := 1; i < 128; i++ {
		q -= q >> 5
		p[128-i] = q >> 20
		p[128+i] = (-q) >> 20
	}
	return p
}()

func (r *rans) stateBit(state *byte) bool {
	r.swap()
	if !r.ok() {
		return false
	}
	f := stateFreq[*state]
	if r.s0&4095 < f {
		r.s0 = f*(r.s0>>12) + (r.s0 & 4095)
		*state = fsmNext1[*state]
		return true
	}
	r.s0 -= f * ((r.s0 >> 12) + 1)
	*state = fsmNext0[*state]
	return false
}

type uintModel [64]byte

func (m *uintModel) init() {
	for i := range m {
		m[i] = 128
	}
}
func (m *uintModel) decode(r *rans) uint64 {
	index := 1
	for i := 0; i < 6; i++ {
		v := 0
		if r.stateBit(&m[index]) {
			v = 1
		}
		index = 2*index + v
	}
	n := index & 63
	var v uint64
	if n > 32 {
		v = uint64(r.bits(n-32)) << 32
		v |= uint64(r.bits(32))
	} else if n != 0 {
		v = uint64(r.bits(n))
	}
	return (uint64(1)<<n | v) - 1
}

func decodeFrames(frames [][]byte, limit int) ([]byte, error) {
	if len(frames) == 0 {
		return []byte{}, nil
	}
	d := newDec(nil, limit)
	d.r.frames = frames
	for !d.r.finished() {
		before := d.pos
		if !d.decodeByte() || d.pos <= before {
			why := d.why
			if why == "" {
				why = "no progress"
			}
			return nil, fmt.Errorf("rzw: decode stuck at output %d/%d (%s; frames_left=%d rans_ok=%v)",
				before, limit, why, len(d.r.frames), d.r.ok())
		}
	}
	return d.out, nil
}

type duplicate struct{ start, source, length int }

func readDuplicates(frames [][]byte, window uint32, size int) ([]duplicate, int, error) {
	r := rans{frames: frames}
	var m [3]uintModel
	for i := range m {
		m[i].init()
	}
	count := m[0].decode(&r)
	rawSize := m[0].decode(&r)
	if count > uint64(size/256) || rawSize > uint64(size) {
		return nil, 0, fmt.Errorf("rzw: invalid duplicate limits: count=%d raw=%d size=%d", count, rawSize, size)
	}
	exp := max(16, bits.Len32(window)-6)
	out := make([]duplicate, 0, int(count))
	end := uint64(0)
	for i := uint64(0); i < count; i++ {
		delta := m[0].decode(&r)
		if delta > uint64(size)-end {
			return nil, 0, fmt.Errorf("rzw: invalid duplicate start")
		}
		start := end + delta
		shift := 8
		if start>>uint(exp+8) != 0 {
			shift = min(16, bits.Len64(start)-exp)
		}
		back := m[1].decode(&r)
		units := m[2].decode(&r)
		if back > start>>shift || units >= uint64(size)>>shift {
			return nil, 0, fmt.Errorf("rzw: invalid duplicate source/length")
		}
		source := ((start >> shift) - back) << shift
		n := (units + 1) << shift
		if source >= start || n > uint64(size)-start {
			return nil, 0, fmt.Errorf("rzw: invalid duplicate range")
		}
		out = append(out, duplicate{int(start), int(source), int(n)})
		end = start + n
	}
	if !r.finished() {
		return nil, 0, fmt.Errorf("rzw: trailing duplicate symbols")
	}
	return out, int(rawSize), nil
}

// The instruction transform reads 64 KiB blocks of the deduplicated file.
// It separates three classes of x86 operands into logical stream two, with
// decisions in stream three and the remaining bytes in stream four.
// Reference: rz 1.00, 0x401620 and 0x4155d0.
func restoreInstructions(frames [][]byte, data, operands []byte, size int) ([]byte, error) {
	r := rans{frames: frames}
	enabled := byte(128)
	var states [288]byte
	for i := range states {
		states[i] = 128
	}
	out := make([]byte, 0, size)
	base := uint32(0)
	for len(out) < size {
		n := min(65536, size-len(out))
		if !r.stateBit(&enabled) {
			if len(data) < n {
				return nil, fmt.Errorf("rzw: truncated instruction data")
			}
			out = append(out, data[:n]...)
			data = data[n:]
			base += uint32(n)
			continue
		}
		var counts [3]int
		total := 0
		for i := range counts {
			exp := r.bits(5)
			v := uint32(1) << exp
			if exp != 0 {
				v |= r.bits(int(exp))
			}
			if v > uint32(n/4)+1 {
				return nil, fmt.Errorf("rzw: invalid operand count")
			}
			counts[i] = 4 * int(v-1)
			total += counts[i]
		}
		if total > n || len(operands) < total || len(data) < n-total || n-total < 2 {
			return nil, fmt.Errorf("rzw: truncated operand streams")
		}
		var groups [3][]byte
		end := total
		for i, c := range counts {
			groups[i] = operands[end-c : end]
			end -= c
		}
		operands = operands[total:]
		src := data[:n-total]
		data = data[n-total:]
		block := make([]byte, n)
		copy(block[:2], src[:2])
		src = src[2:]
		j := 2
		for j < n-4 {
			if len(src) == 0 {
				return nil, fmt.Errorf("rzw: missing opcode byte")
			}
			block[j] = src[0]
			src = src[1:]
			next := j + 1
			if next > 9 {
				p := block[next-10:]
				if binary.LittleEndian.Uint16(p) == 0x5a4d && binary.LittleEndian.Uint16(p[2:]) <= 0x200 && binary.LittleEndian.Uint16(p[8:]) <= 0x100 || binary.LittleEndian.Uint32(p) == 0x4550 && binary.LittleEndian.Uint16(p[6:]) <= 0x60 {
					base = ^uint32(j)
				}
			}
			v := uint32(block[j-2]) | uint32(block[j-1])<<8 | uint32(block[j])<<16
			group, ctx := -1, 0
			switch {
			case v&0xfe0000 == 0xe80000:
				group = int(v >> 16 & 1)
				ctx = int(block[j-1])
			case v&0xf0ff00 == 0x800f00:
				group = 1
				ctx = 128 + int(block[j])
			case v&0xc7f0fb == 0x058048:
				group = 2
				ctx = 144 + int(block[j-1])
			}
			if group >= 0 {
				if ctx >= len(states) {
					return nil, fmt.Errorf("rzw: invalid opcode context")
				}
				if r.stateBit(&states[ctx]) {
					if len(groups[group]) < 4 {
						return nil, fmt.Errorf("rzw: missing operand")
					}
					target := binary.LittleEndian.Uint32(groups[group])
					groups[group] = groups[group][4:]
					rel := int32(target-uint32(next)-base) << 8 >> 8
					binary.LittleEndian.PutUint32(block[next:], uint32(rel))
					next += 4
				}
			}
			j = next
		}
		if len(src) != n-j {
			return nil, fmt.Errorf("rzw: unused instruction bytes: %d != %d", len(src), n-j)
		}
		copy(block[j:], src)
		for _, g := range groups {
			if len(g) != 0 {
				return nil, fmt.Errorf("rzw: unused operands")
			}
		}
		out = append(out, block...)
		base += uint32(n)
	}
	if len(data) != 0 || len(operands) != 0 || !r.finished() {
		return nil, fmt.Errorf("rzw: trailing instruction data")
	}
	return out, nil
}

func restoreDuplicates(data []byte, records []duplicate, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	for _, rec := range records {
		gap := rec.start - len(out)
		if gap < 0 || gap > len(data) {
			return nil, fmt.Errorf("rzw: truncated unique data")
		}
		out = append(out, data[:gap]...)
		data = data[gap:]
		if rec.source >= len(out) || rec.length > size-len(out) {
			return nil, fmt.Errorf("rzw: invalid duplicate")
		}
		for i := 0; i < rec.length; i++ {
			out = append(out, out[rec.source+i])
		}
	}
	out = append(out, data...)
	if len(out) != size {
		return nil, fmt.Errorf("rzw: restored size %d != %d", len(out), size)
	}
	return out, nil
}
