package mpzz

import (
	"fmt"
	"math/bits"
	"sort"
)

// 0x1000b010 assigns the first available prefix in entry order. Vorbis
// transmits each codeword least-significant bit first.
func (b *codebook) buildCodes() error {
	b.codes = make([]uint32, len(b.lengths))
	var available [33]uint32
	first := true
	for i, length := range b.lengths {
		if length == 0 {
			continue
		}
		if length > 32 {
			return fmt.Errorf("invalid Huffman length %d", length)
		}
		if first {
			first = false
			for n := 1; n <= int(length); n++ {
				available[n] = 1 << (32 - n)
			}
			continue
		}
		n := int(length)
		for n > 0 && available[n] == 0 {
			n--
		}
		if n == 0 {
			return fmt.Errorf("oversubscribed Huffman tree")
		}
		code := available[n]
		available[n] = 0
		b.codes[i] = bits.Reverse32(code)
		for n++; n <= int(length); n++ {
			available[n] = code + 1<<(32-n)
		}
	}
	return nil
}

func (b *codebook) write(w *bitWriter, symbol int) error {
	if symbol < 0 || symbol >= len(b.lengths) || b.lengths[symbol] == 0 {
		return fmt.Errorf("mpzz: invalid Huffman symbol %d (entries %d)", symbol, len(b.lengths))
	}
	w.write(b.codes[symbol], uint(b.lengths[symbol]))
	return nil
}

type audioDecoder struct {
	residueHistory                                    [1 << 20]byte
	componentPresent, componentSign, componentLength  [4]uint32
	lastContext                                       int
	setup                                             *vorbisSetup
	body, header, aux                                 *rangeDecoder
	models                                            []integerModel
	probs                                             []uint16
	channels                                          int
	blocks                                            [2]int
	modeHistory, prevWindow, nextWindow, floorHistory uint32
	floorLengths                                      [64][256]byte
	granule                                           uint32
	w                                                 bitWriter
	leftover                                          []byte
}

func (a *audioDecoder) tree(r *rangeDecoder, base, n int) uint32 {
	v := 1
	for range n {
		idx := base + v
		if idx < 0 || idx >= len(a.probs) {
			r.err = fmt.Errorf("mpzz: probability offset %#x out of bounds", idx)
			return 0
		}
		v = 2*v + int(r.bit(&a.probs[idx]))
	}
	return uint32(v & ((1 << n) - 1))
}

// 0x1001e020: modes and long-window flags belong to the page range.
func (a *audioDecoder) mode(flags byte) (modeConfig, error) {
	a.w = bitWriter{}
	a.w.write(0, 1)
	ctx := uint32(flags&1) + 2*a.modeHistory + 4*a.nextWindow
	n := bits.Len(uint(len(a.setup.modes) - 1))
	m := a.tree(a.header, int(ctx)<<6, n)
	if int(m) >= len(a.setup.modes) {
		return modeConfig{}, fmt.Errorf("mpzz: invalid audio mode %d", m)
	}
	a.w.write(m, uint(n))
	a.modeHistory = m & 1
	mode := a.setup.modes[m]
	block := 0
	if mode.large {
		block = 1
	}
	a.granule += uint32(a.blocks[block] / 2)
	prev, next := uint32(0), uint32(0)
	if mode.large {
		prev = a.header.bit(&a.probs[0x201+a.nextWindow])
		next = a.header.bit(&a.probs[0x205+a.prevWindow])
		a.w.write(prev, 1)
		a.w.write(next, 1)
	}
	a.prevWindow, a.nextWindow = prev, next
	return mode, a.header.err
}

// 0x10002790 decodes floor values in ascending X order, then restores
// the class selector and subbook codewords from those values.
func (a *audioDecoder) floors(mapping mappingConfig) ([]bool, error) {
	silent := make([]bool, a.channels)
	for ch := range a.channels {
		floor := mapping.floors[mapping.mux[ch]]
		f := a.setup.floors[floor]
		present := a.body.bit(&a.probs[0x2255+a.floorHistory])
		a.floorHistory = (2*a.floorHistory + present) & 3
		a.w.write(present, 1)
		if present == 0 {
			silent[ch] = true
			continue
		}
		order := make([]int, len(f.x))
		for i := range order {
			order[i] = i
		}
		sort.Slice(order, func(i, j int) bool { return f.x[order[i]] < f.x[order[j]] })
		y := make([]int, len(f.x))
		history := 0
		for _, i := range order {
			present := a.body.bit(&a.probs[0x225c+history*128+floor+i*4])
			history = (history*2 + int(present)) & 3
			n := 0
			if present != 0 {
				n = int(a.tree(a.body, 0x1225c+floor*8+i*32+int(a.floorLengths[floor][i])*1024, 3))
				v, hist := 1, 0
				for j := range n {
					base := 0x2225c + floor*32 + i*8192 + n*132 - 4 + hist - 4*j
					b := int(a.body.bit(&a.probs[base]))
					v = 2*v + b
					hist = (2*hist + b) & 3
				}
				y[i] = v
			}
			a.floorLengths[floor][i] = byte(n)
		}
		n := uint(bits.Len(uint([]int{256, 128, 86, 64}[f.mult-1] - 1)))
		a.w.write(uint32(y[0]), n)
		a.w.write(uint32(y[1]), n)
		pos := 2
		for _, idx := range f.partitions {
			cl := f.classes[idx]
			selectors := make([]int, cl.dim)
			if cl.sub > 0 {
				cval := 0
				for j := range cl.dim {
					found := false
					for k, book := range cl.books {
						entries := 1
						if book >= 0 {
							entries = len(a.setup.books[book].lengths)
						}
						if y[pos+j] < entries {
							selectors[j], found = k, true
							break
						}
					}
					if !found {
						return nil, fmt.Errorf("mpzz: floor value %d exceeds subbooks", y[pos+j])
					}
					cval |= selectors[j] << (j * cl.sub)
				}
				if err := a.setup.books[cl.master].write(&a.w, cval); err != nil {
					return nil, err
				}
			}
			for j, selector := range selectors {
				book := cl.books[selector]
				if book >= 0 {
					if err := a.setup.books[book].write(&a.w, y[pos+j]); err != nil {
						return nil, err
					}
				}
			}
			pos += cl.dim
		}
	}
	return silent, a.body.err
}

// 0x10003b50 retains extra packet bytes. Zero padding has its own flag;
// nonzero padding is coded with the preceding byte's high nibble.
func (a *audioDecoder) finishPacket(size int) error {
	if len(a.w.data) > size {
		return fmt.Errorf("mpzz: packet exceeds stored length: %d > %d", len(a.w.data), size)
	}
	a.w.n = uint(len(a.w.data) * 8)
	if len(a.w.data) < size {
		zero := a.body.bit(&a.probs[0x214])
		prev := 0
		for len(a.w.data) < size {
			v := uint32(0)
			if zero == 0 {
				v = a.tree(a.body, 0x218+(prev&0xf0)*16, 8)
			}
			a.w.write(v, 8)
			prev = int(v)
		}
	}
	return a.body.err
}
