package xt2png

import (
	"encoding/binary"
	"fmt"
)

const (
	pngSig    = 0x0A1A0A0D474E5089
	pngIHDR   = 0x52444849
	pngIDAT   = 0x54414449
	pngIEND   = 0x444E4549
	pngHdrLen = 8
)

// decodePNG inverts EncodePNG in PrecompZLib.pas: signature is PNG_SIG+1,
// IDAT payloads are concatenated after the structure that keeps only
// size+type+CRC for those chunks.
func decodePNG(in []byte, want int) ([]byte, error) {
	if len(in) < 16 {
		return nil, fmt.Errorf("xt2png: short png")
	}
	if binary.LittleEndian.Uint64(in[:8]) != pngSig+1 {
		return nil, fmt.Errorf("xt2png: png signature sig=%016x len=%d want=%d", binary.LittleEndian.Uint64(in[:8]), len(in), want)
	}
	if binary.LittleEndian.Uint32(in[12:16]) != pngIHDR {
		return nil, fmt.Errorf("xt2png: png header")
	}
	out := make([]byte, 0, max(want, len(in)))
	var sig [8]byte
	binary.LittleEndian.PutUint64(sig[:], pngSig)
	out = append(out, sig[:]...)
	readPos := 0
	for pass := 1; pass <= 2; pass++ {
		cur := 8
		outPos := 8
		if pass == 2 {
			out = out[:8]
		}
		for {
			if cur+8 > len(in) {
				return nil, fmt.Errorf("xt2png: png chunk")
			}
			size := int(int32(binary.BigEndian.Uint32(in[cur:])))
			header := binary.LittleEndian.Uint32(in[cur+4:])
			if size < 0 || cur+8+4 > len(in) {
				return nil, fmt.Errorf("xt2png: png size")
			}
			if header == pngIEND {
				n := 8 + size + 4
				if pass == 2 {
					if cur+n > len(in) {
						return nil, fmt.Errorf("xt2png: png end")
					}
					out = append(out, in[cur:cur+n]...)
				}
				if pass == 1 {
					readPos = cur + n
				}
				break
			}
			if header == pngIDAT {
				if pass == 2 {
					if cur+8+4 > len(in) || readPos+size > len(in) {
						return nil, fmt.Errorf("xt2png: png idat")
					}
					out = append(out, in[cur:cur+8]...)
					out = append(out, in[readPos:readPos+size]...)
					out = append(out, in[cur+8:cur+12]...)
					readPos += size
				}
				cur += 8 + 4
			} else {
				n := 8 + size + 4
				if cur+n > len(in) {
					return nil, fmt.Errorf("xt2png: png other")
				}
				if pass == 2 {
					out = append(out, in[cur:cur+n]...)
				}
				cur += n
			}
			_ = outPos
		}
	}
	return out, nil
}
