// Package godec — CRC32-IEEE verification for magic2 application marker.
//
// magic2_decode (main.cpp:1608) retries decode_v22 across the
// (use_second, use_hdr, opt_skip, force_opt, cls11_mode) variants and
// accepts the first whose output carries the magic2 application marker
// at offset kEmu. The marker is the IEEE-802.3 CRC of a 6-byte fixed
// prefix — the same polynomial FreeArc uses for its chunk integrity
// tags, just over the magic2 "magic2l" signature block instead of a
// chunk trailer.
package godec

// Application-marker offset and length. main.cpp:18-19.
//
// kEmu is the byte offset where the application marker starts inside
// the decoded buffer. The decoder runs the magic2 emulator (LZ ring
// buffer + ROLZ hash chain) for kEmu bytes before the application
// payload — the marker is the first six bytes of that payload.
//
// kApp is the marker length: a 6-byte fixed prefix whose IEEE CRC
// must match kAppCRC for hit_crc to fire.
const (
	kEmu    = 2895
	kApp    = 6
	kAppCRC = 0xf75982bb
)

// crc32IEEE computes the IEEE-802.3 CRC32 (poly 0xEDB88320 reflected)
// over the first n bytes of p. Mirrors main.cpp:654 (crc32_ieee).
//
// The reflection (`(c >> 1) ^ (0xEDB88320 & mask)` with mask = -(c&1))
// matches the C cast `0xedb88320u & (uint32_t)-(int32_t)(c & 1)`. The
// XOR-with-0xFF on exit is the IEEE convention; it differs from the
// raw polynomial CRC that some other protocols use.
func crc32IEEE(p []byte, n int) uint32 {
	if n > len(p) {
		n = len(p)
	}
	var c uint32 = 0xffffffff
	for i := 0; i < n; i++ {
		c ^= uint32(p[i])
		for b := 0; b < 8; b++ {
			mask := uint32(0) - (c & 1)
			c = (c >> 1) ^ (0xedb88320 & mask)
		}
	}
	return ^c
}

// hitCRC returns true when dst[0:n] carries the magic2 application
// marker at offset kEmu. Mirrors main.cpp:770-772 (hit_crc).
//
// The bound check (`n < kEmu + kApp`) collapses every short output —
// EOF, sub-header input, rANS underrun before kEmu bytes — to false
// without indexing past the buffer. The hit only fires when the
// caller has decoded at least the emulator prefix AND the application
// payload's first six bytes CRC to kAppCRC.
func hitCRC(dst []byte, n int) bool {
	if n < kEmu+kApp {
		return false
	}
	return crc32IEEE(dst[kEmu:kEmu+kApp], kApp) == kAppCRC
}
