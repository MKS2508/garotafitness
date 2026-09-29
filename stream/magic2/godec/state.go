// Package godec is the magic2 rANS decoder state machine — the per-stream core
// that read_v22, decode_bc0, decode_int_pe, get_nibble, and get_sym8 all pivot
// through. Direct port of garotafitness-fork stream/magic2/guest/main.cpp
// (Rans struct + renorm + get_bit, lines 14, 224-260).
package godec

// Rans is the per-stream rANS decoder state. Holds between decode calls; in the
// PE this lives in a 0x4a8-byte allocation, in Go we keep it as a *Rans the
// caller threads through its loop.
type Rans struct {
	X   uint32 // renormalized to >= kL between decodes
	Buf []byte // bitstream slice (not owned; caller holds the buffer)
	Off int    // next byte consumed by Renorm
	Len int    // total length of Buf
	OK  bool   // false once a Renorm underruns
}

// kL is the rANS renormalization lower bound. main.cpp:14.
const kL uint32 = 1 << 23

// Renorm mirrors main.cpp renorm (lines 231-239): while X < kL and input
// remains, fold the next byte into the high 8 bits of X. Sets OK=false on
// underrun so subsequent GetBit calls short-circuit with -1.
func (r *Rans) Renorm() {
	for r.X < kL {
		if r.Off >= r.Len {
			r.OK = false
			return
		}
		r.X = (r.X << 8) | uint32(r.Buf[r.Off])
		r.Off++
	}
}

// GetBit mirrors main.cpp get_bit (lines 241-260). p0 is updated in place —
// adaptive coding nudges the probability toward the observed symbol each call.
// nbits is the precision (every site in the current callers uses 14).
// shift controls how aggressively p0 tracks (4 for class-1 / extra-bits
// tables, 5 for the rest).
//
// Returns 0/1 on success and -1 if the stream is exhausted.
func (r *Rans) GetBit(p0 *uint16, nbits, shift uint) int {
	if !r.OK {
		return -1
	}
	m := uint32(1) << nbits
	p := uint32(*p0)
	if p >= m && p != 0 {
		p = m - 1
	}
	slot := r.X & (m - 1)
	quo := r.X >> nbits
	if slot < p {
		r.X = quo*p + slot
		*p0 = uint16(p + ((m - p) >> shift))
		r.Renorm()
		return 0
	}
	r.X = r.X - p*(quo+1)
	np := p - (p >> shift)
	if np == 0 {
		np = 1
	}
	*p0 = uint16(np)
	r.Renorm()
	return 1
}

// Per-stream module-scope globals from the cls-magic2 PE live as State
// fields (see decode.go's State struct), not as package-level vars:
// they need to persist across chunk-group calls alongside RingBuffer
// and HashChain, and putting them in State keeps the per-stream working
// set in one place.
//
// The one PE global that does NOT live in State is gRolz / gRolzCur
// (main.cpp:606-607) — that data already lives inside ROLZ.HashChain
// (lz.go) as `List [256][RolzCap]uint32` and `Cur [256]uint32`. A
// package-level gRolz would be duplicate state and drift apart from
// HashChain.List on the first call.