package godec

// abs32 returns |x| as uint32. main.cpp:643 — `static uint32_t
// abs32(int32_t x) { return x < 0 ? (uint32_t)(-x) : (uint32_t)x; }`.
// Used by the Hist shift register (ApplySample) and hist_h1's row
// distance.
func abs32(x int32) uint32 {
	if x < 0 {
		return uint32(-x)
	}
	return uint32(x)
}

// NewLE mirrors the Rans initializer used by decode_iir (main.cpp:778-783):
// the first 4 bytes of buf are read little-endian into X, Off starts at 4 so
// the first Renorm call pulls fresh bytes, and we run Renorm once to clear
// the underrun flag if buf happens to be smaller than kL.
//
// Caller must guarantee len(buf) >= 4 — matches the C++ contract where every
// constructor site is wrapped in a slen check (decode_iir, the wr at line
// 1162, and the decode_v22 site).
func NewLE(buf []byte) *Rans {
	r := &Rans{
		Buf: buf,
		Off: 4,
		Len: len(buf),
		OK:  true,
		X:   uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24,
	}
	r.Renorm()
	return r
}