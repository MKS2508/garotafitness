// Package magic2 — framing oracle.
//
// The shipped magic2dec.wasm guest exports magic2_decode(src, slen, dst, dcap)
// -> bytes_written, which decodes exactly one chunk-group per call. To decode
// a multi-group FitGirl solid, the host needs to know where each chunk-group
// begins and ends.
//
// Real frame layout (post the 9-byte magic2 header), per RE of cls-magic2
// and handoff §2 (pre-5ec2107 reader.go had this format):
//
//	for each frame (until EOF):
//	  uint16 capacity_hint           // 2 bytes LE — pre-5ec2107 used this to skip
//	  uint32 metadata_size           // 0 => EOF trailer; else bytes of metadata block
//	  [metadata_size]byte metadata   // self-terminating rANS stream; first 4 bytes
//	                                  // are the initial rANS state
//	  for each chunk-group in the frame:
//	    uint32 chunk_size            // LE bytes of body that follows
//	    [chunk_size]byte body        // opt_header + payload, handed to magic2_decode
//
// On FitGirl each frame carries exactly one chunk-group, so we deliver one
// body range per Next() call.
package magic2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// metadataFraming locates chunk-group byte ranges by parsing the per-frame
// metadata stream + per-chunk 4-byte size prefix.
type metadataFraming struct {
	src     io.ReaderAt
	bodyOff int64
}

// Next reads from `from` and returns (start, end) of the first chunk-group body.
// EOF when the stream is exhausted.
func (f metadataFraming) Next(from, total int64) (int64, int64, error) {
	if from < 0 || total < 0 {
		return 0, 0, fmt.Errorf("magic2: framing cursor %d total %d", from, total)
	}
	if from >= total {
		return 0, 0, io.EOF
	}

	// Frame header: 2 bytes capacity_hint + 4 bytes metadata_size.
	if total-from < 6 {
		return 0, 0, io.EOF
	}
	var hdr [6]byte
	sec := io.NewSectionReader(f.src, f.bodyOff+from, 6)
	if _, err := io.ReadFull(sec, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, 0, io.EOF
		}
		return 0, 0, fmt.Errorf("magic2: read frame header at %d: %w", from, err)
	}
	capacity := binary.LittleEndian.Uint16(hdr[0:2])
	metaSize := binary.LittleEndian.Uint32(hdr[2:6])

	// EOF trailer: 4-byte zero metadata_size (after the 2-byte capacity hint,
	// which itself can be zero or the last capacity from the previous frame).
	// Detect EOF: if the 6-byte header reads as either all zeros, or metadata_size==0.
	if metaSize == 0 {
		return 0, 0, io.EOF
	}
	if metaSize < 4 || int64(metaSize) > total-from-6 || metaSize > 1<<24 {
		return 0, 0, fmt.Errorf("%w: metadata size=%d (capacity=%d) at %d", errBitstream, metaSize, capacity, from)
	}

	// Read metadata block (rANS state + segment options).
	metaBuf := make([]byte, metaSize)
	sec = io.NewSectionReader(f.src, f.bodyOff+from+6, int64(metaSize))
	if _, err := io.ReadFull(sec, metaBuf); err != nil {
		return 0, 0, fmt.Errorf("magic2: read metadata at %d: %w", from, err)
	}
	meta := newMetadata(metaBuf)
	seg, err := meta.next()
	if err != nil {
		return 0, 0, fmt.Errorf("magic2: parse metadata at %d: %w", from, err)
	}
	if seg.packed == 0 {
		return 0, 0, fmt.Errorf("%w: zero-size chunk-group at %d", errBitstream, from)
	}

	// Position now: end of metadata block. Next comes the chunk-group body
	// prefixed by its own 4-byte LE chunk_size.
	bodyStartInFrame := int64(6) + int64(metaSize)
	if total-from < bodyStartInFrame+4 {
		return 0, 0, fmt.Errorf("%w: chunk-size missing after metadata at %d", errBitstream, from)
	}
	var chunkHdr [4]byte
	sec = io.NewSectionReader(f.src, f.bodyOff+from+bodyStartInFrame, 4)
	if _, err := io.ReadFull(sec, chunkHdr[:]); err != nil {
		return 0, 0, fmt.Errorf("magic2: read chunk-size at %d: %w", from, err)
	}
	chunkSize := binary.LittleEndian.Uint32(chunkHdr[:])
	if chunkSize == 0 || int64(chunkSize) > int64(seg.packed)+64 || int64(chunkSize) < int64(seg.packed)-64 {
		// Allow off-by-some-bytes because the kernel may pad or trim; warn but
		// still treat seg.packed as the authoritative size from the metadata.
		chunkSize = seg.packed
	}

	start := from + bodyStartInFrame + 4
	end := start + int64(chunkSize)
	if end > total {
		return 0, 0, fmt.Errorf("%w: chunk-group [%d,%d) exceeds body %d", errBitstream, start, end, total)
	}
	return start, end, nil
}
