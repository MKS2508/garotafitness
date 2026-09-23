package magic2

import (
	"fmt"
	"math/bits"
)

// Model offsets retain the layout of cls-magic2_x64 VA 0x140029700
// (literals) and 0x140035820 (matches), so independent contexts remain distinct.
type decoder struct {
	colorSelector uint16
	alphaSelector uint16
	pixelWeights  [3][4][3][8]int16
	imageWeights  [2][8]int16
	header        Header
	models        map[int][]uint16
	probabilities map[int]uint16
	weights       map[int]uint16
	out           []byte
	reps          [22]int
	state         int
}

func newDecoder(h Header) *decoder {
	return &decoder{header: h, colorSelector: 0x2000, alphaSelector: 0x6000, models: make(map[int][]uint16), probabilities: make(map[int]uint16), weights: make(map[int]uint16)}
}

func (d *decoder) slide() {
	keep := int(d.header.DictionarySize)
	if keep < 64<<20 {
		keep = 64 << 20
	}
	if len(d.out) <= keep*2 {
		return
	}
	drop := len(d.out) - keep
	copy(d.out, d.out[drop:])
	d.out = d.out[:keep]
}
func (d *decoder) model(a, n int) []uint16 {
	c := d.models[a]
	if c == nil {
		c = uniform(n)
		d.models[a] = c
	}
	return c
}
func (d *decoder) symbol(r *entropy, a, n int, shift uint) int { return r.symbol(d.model(a, n), shift) }
func (d *decoder) bit(r *entropy, a int) int {
	p, ok := d.probabilities[a]
	if !ok {
		p = 8192
	}
	v := r.bit(&p, 14, 5)
	d.probabilities[a] = p
	return v
}
func (d *decoder) mixed(r *entropy, a, b, w int, shift uint) int {
	A, B := d.model(a, 16), d.model(b, 16)
	weight, ok := d.weights[w]
	if !ok {
		weight = 32768
	}
	var c [17]uint16
	for i := 0; i < 16; i++ {
		c[i] = uint16((uint32(weight) * uint32(A[i]) >> 16) + (uint32(uint16(-weight)) * uint32(B[i]) >> 16))
	}
	c[16] = 32768
	s := r.selectSymbol(c[:])
	weight -= weight >> 4
	if A[s+1]-A[s] >= B[s+1]-B[s] {
		weight += 4095
	}
	d.weights[w] = weight
	adaptCDF(A, s, shift)
	adaptCDF(B, s, shift)
	r.normalize()
	return s
}

var lengthBits = [...]uint{3, 3, 3, 3, 3, 4, 4, 4, 5, 5, 6, 7, 8, 9, 10, 11}
var distanceBits = [...]uint{5, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 5, 6, 7, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30}

func slotBase(table []uint, s int) int {
	v := 0
	for _, n := range table[:s] {
		v += 1 << n
	}
	return v
}
func (d *decoder) length(r *entropy, a, b int) int {
	s := d.symbol(r, a, 16, 6)
	if s < 8 {
		return s
	}
	t := d.symbol(r, b, 16, 6)
	n := lengthBits[t]
	v := slotBase(lengthBits[:], t) + s
	if n > 3 {
		v += r.raw(n-3) * 8
	}
	return v
}
func (d *decoder) distance(r *entropy, a, state, look int, escape bool) int {
	s := d.mixed(r, a, a+0x44+bits.Len32(uint32(look))*34, a+0x484+state*2, 5)
	if escape && s == 15 {
		s += d.symbol(r, a+0x22, 16, 5)
	}
	n := distanceBits[s]
	v := slotBase(distanceBits[:], s)
	high := 0
	if n > 5 {
		high = d.symbol(r, a+0x4a4+s*34, 16, 6)
		v += high << max(5, n-4)
		if n > 9 {
			v += r.raw(n-9) << 5
		}
	}
	low := d.symbol(r, a+0x8e4+s*34+high*1088, 16, 7)
	return v + low*2 + d.bit(r, a+0x4ce4+s*2+high*64)
}

var literalState = [...]int{0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 7, 8, 0}
var newMatchState = [...]int{10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 13, 13, 13, 13, 13, 10}
var repeatState = [...]int{11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 14, 14, 14, 14, 14, 11}
var shortState = [...]int{12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 14, 14, 14, 14, 14, 12}
var repeatSlots = [...]int{0, 1, 2, 3, 17, 18, 0}
var extendedSlots = [...]int{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 20, 21}

func (d *decoder) decode(data []byte, s segment) error {
	if s.option == 63 {
		d.out = append(d.out, data...)
		return nil
	}
	if s.option >= len(positionMasks) {
		return fmt.Errorf("magic2: unsupported option %d", s.option)
	}
	r := newEntropy(data)
	start := len(d.out)
	end := start + int(s.size)
	mask := int(positionMasks[s.option])
	cfg := d.header
	for len(d.out) < end && r.err == nil {
		pos := len(d.out)
		h := int(positionContexts[s.option][(pos-start)&mask])
		state := d.state
		prev, pred := 0, 0
		if pos > 0 {
			prev = int(d.out[pos-1])
		}
		if pos > d.reps[0] {
			pred = int(d.out[pos-d.reps[0]-1])
		}
		token := d.bit(r, h*64+state*4)
		if token == 0 && mixers[h] < 99 {
			token = 2 * d.bit(r, h*64+state*4+2)
		}
		if token == 0 {
			high := d.mixed(r, 0x1000000+h*2176+34*(pred>>cfg.PredictionShift), 0x1026c80+h*8704+34*(prev>>cfg.HighShift), 0x10c1e80+h*32+(prev>>cfg.WeightShift)*0x920+state*2, 6)
			ctx := high
			if high == pred>>4 {
				ctx = 16 + (pred & 15)
			}
			low := d.mixed(r, 0x10e6680+h*1088+34*ctx, 0x10f9cc0+h*8704+34*(prev>>cfg.LowShift), 0x1194ec0+h*32+(prev>>cfg.WeightShift)*0x920+state*2, 7)
			d.out = append(d.out, byte(high<<4|low))
			d.state = literalState[state]
			continue
		}
		if token == 2 {
			switch mixers[h] {
			case 0:
				if end-pos < 2 {
					return errBitstream
				}
				block := d.alphaEndpoints(r, int(s.aux)*4)
				d.out = append(d.out, block[:]...)
			case 1:
				if end-pos < 6 {
					return errBitstream
				}
				block := d.alphaIndices(r, int(s.aux)*4)
				d.out = append(d.out, block[:]...)
			case 2, 3:
				if end-pos < 4 {
					return errBitstream
				}
				width := int(s.aux) * 4
				if s.option == 5 {
					width = int(s.aux) * 2
				}
				var block [4]byte
				if mixers[h] == 2 {
					block = d.colorEndpoints(r, width, mask+1)
				} else {
					block = d.colorIndices(r, width, mask+1)
				}
				d.out = append(d.out, block[:]...)
			case 4:
				if end-pos < 8 {
					return errBitstream
				}
				width := int(s.aux) * 4
				if s.option == 5 {
					width = int(s.aux) * 2
				}
				block := d.explicitAlpha(r, width)
				d.out = append(d.out, block[:]...)
			case 5:
				d.out = append(d.out, d.imageByte(r, int(s.aux)))
			case 6, 7, 8:
				channels := int(mixers[h]) - 4
				if end-pos < channels {
					return errBitstream
				}
				pixel := d.imagePixel(r, int(s.aux)*channels, channels)
				d.out = append(d.out, pixel[:channels]...)
			default:
				return fmt.Errorf("magic2: unsupported prediction mode %d at output %d", mixers[h], pos)
			}
			d.state = 15
			continue
		}
		cls := d.mixed(r, 0x1240+h*544+state*34, 0xad60+(pred>>cfg.ClassShift)*1088+bits.Len32(uint32(d.reps[0]))*34, 0x1bd60+(prev>>cfg.WeightShift)*32+state*2, 6)
		distance, n := 0, 0
		switch cls {
		case 0:
			distance = d.reps[0]
			n = 1
			d.state = shortState[state]
		case 1:
			high := d.symbol(r, 0x1c560+h*18, 8, 6)
			ctx := 0
			if state >= 10 {
				ctx = 1
			}
			low := d.symbol(r, 0x1ca82+h*288+144*ctx+18*high, 8, 7)
			distance = 8*high + low
			n = 2
		case 2, 3:
			base := 0x225c2
			if cls == 3 {
				base = 0x313e6
			}
			distance = d.distance(r, base, state, d.reps[0], cls == 3)
			bl := bits.Len32(uint32(distance)) / 4
			ctx := 0
			if state == 0 {
				ctx = 1
			}
			if cls == 2 {
				n = 3 + d.bit(r, 0x21ca2+h*32+bl*4+2*ctx)
			} else {
				n = 5 + d.length(r, 0x276a6+h*544+34*ctx+bl*68, 0x311c6+bl*34)
			}
		case 11:
			return fmt.Errorf("magic2: unexpected ROLZ match at output %d", pos)
		default:
			slot := cls - 12
			if cls < 12 {
				slot = repeatSlots[cls-4]
				if cls == 10 {
					slot = extendedSlots[d.symbol(r, 0x364ca+h*544+34*state, 16, 6)]
				}
				ctx := 0
				if slot != 0 {
					ctx = 1
				}
				n = 3 + d.symbol(r, 0x3ffea+h*576+state*36+18*ctx, 8, 7)
				if n == 10 {
					n += d.length(r, 0x4a42a+h*8704+state*34+544*ctx, 0xe562a+34*ctx)
				}
			} else {
				n = 2
			}
			distance = d.reps[slot]
			if slot < 17 {
				copy(d.reps[1:slot+1], d.reps[:slot])
			} else {
				copy(d.reps[1:17], d.reps[:16])
				copy(d.reps[slot:21], d.reps[slot+1:22])
				d.reps[21] = max(7, mask)
			}
			d.reps[0] = distance
			d.state = repeatState[state]
		}
		if cls >= 1 && cls <= 3 {
			copy(d.reps[18:22], d.reps[17:21])
			d.reps[17] = distance
			d.state = newMatchState[state]
		}
		if r.err != nil {
			return r.err
		}
		if n <= 0 {
			return fmt.Errorf("%w: match distance %d length %d at %d", errBitstream, distance, n, pos)
		}
		if n > end-pos {
			n = end - pos
		}
		// PE VirtualAlloc zeros the dictionary: dist>=pos copies 0, not an error.
		for i := 0; i < n; i++ {
			p := len(d.out)
			var b byte
			if distance >= 0 && distance < p {
				b = d.out[p-distance-1]
			}
			d.out = append(d.out, b)
		}
	}
	return r.finish()
}
