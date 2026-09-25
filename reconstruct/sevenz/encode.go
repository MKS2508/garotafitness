// Package sevenz writes the non-solid LZMA 7z archives used by the installer.
package sevenz

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"sort"
)

// File is one member packed into the archive.
type File struct {
	Name string
	Data []byte
}

// winArchive is FILE_ATTRIBUTE_ARCHIVE. The installer runs Windows 7z.exe.
const winArchive = 0x20

// Encode writes a 7z archive matching:
// 7z a -ms=off -mtc=off -mtm=off -mta=off -m0=lzma:x=4:d=512k
func Encode(ctx context.Context, files []File) ([]byte, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("sevenz: no files")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	enc, err := newLzmaEnc(ctx)
	if err != nil {
		return nil, err
	}
	defer enc.Close(ctx)
	var biggest uint32
	for _, f := range files {
		if n := uint32(len(f.Data)); n > biggest {
			biggest = n
		}
	}
	opts := fileOpts(roundDict(biggest))
	var packed []byte
	packSizes := make([]uint64, len(files))
	crcs := make([]uint32, len(files))
	sizes := make([]uint64, len(files))
	props := make([][]byte, len(files))
	for i, f := range files {
		body, p, err := lzmaBody(ctx, enc, f.Data, opts)
		if err != nil {
			return nil, err
		}
		props[i] = p
		packSizes[i] = uint64(len(body))
		sizes[i] = uint64(len(f.Data))
		crcs[i] = crc32.ChecksumIEEE(f.Data)
		packed = append(packed, body...)
	}
	return finish(ctx, enc, packed, encodeHeader(files, packSizes, sizes, crcs, props))
}

// WrapPacked writes a 7z archive around already-compressed file bytes.
func WrapPacked(ctx context.Context, files []File, packSizes, unpackSizes []uint64, crcs []uint32, props [][]byte, packed []byte) ([]byte, error) {
	enc, err := newLzmaEnc(ctx)
	if err != nil {
		return nil, err
	}
	defer enc.Close(ctx)
	return finish(ctx, enc, packed, encodeHeader(files, packSizes, unpackSizes, crcs, props))
}

func finish(ctx context.Context, enc *lzmaEnc, packed, raw []byte) ([]byte, error) {
	comp, hprops, err := lzmaBody(ctx, enc, raw, headerOpts())
	if err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	encoded.WriteByte(0x17) // kEncodedHeader
	encoded.WriteByte(0x06) // kPackInfo
	writeNumber(&encoded, uint64(len(packed)))
	writeNumber(&encoded, 1)
	encoded.WriteByte(0x09) // kSize
	writeNumber(&encoded, uint64(len(comp)))
	encoded.WriteByte(0x00)
	encoded.WriteByte(0x07) // kUnpackInfo
	encoded.WriteByte(0x0b) // kFolder
	writeNumber(&encoded, 1)
	encoded.WriteByte(0)
	encoded.WriteByte(1)
	encoded.WriteByte(0x23)
	encoded.Write([]byte{3, 1, 1})
	writeNumber(&encoded, uint64(len(hprops)))
	encoded.Write(hprops)
	encoded.WriteByte(0x0c)
	writeNumber(&encoded, uint64(len(raw)))
	encoded.WriteByte(0x0a)
	encoded.WriteByte(1)
	binary.Write(&encoded, binary.LittleEndian, crc32.ChecksumIEEE(raw))
	encoded.WriteByte(0x00)
	encoded.WriteByte(0x00)

	var out bytes.Buffer
	out.Write([]byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04})
	var start [20]byte
	binary.LittleEndian.PutUint64(start[0:8], uint64(len(packed)+len(comp)))
	binary.LittleEndian.PutUint64(start[8:16], uint64(encoded.Len()))
	binary.LittleEndian.PutUint32(start[16:20], crc32.ChecksumIEEE(encoded.Bytes()))
	var crcField [4]byte
	binary.LittleEndian.PutUint32(crcField[:], crc32.ChecksumIEEE(start[:]))
	out.Write(crcField[:])
	out.Write(start[:])
	out.Write(packed)
	out.Write(comp)
	out.Write(encoded.Bytes())
	return out.Bytes(), nil
}

func roundDict(n uint32) uint32 {
	if n < 4096 {
		return 4096
	}
	for i := uint(11); i <= 19; i++ {
		if n <= 2<<i {
			return 2 << i
		}
		if n <= 3<<i {
			return 3 << i
		}
	}
	return 512 << 10
}

func lzmaBody(ctx context.Context, enc *lzmaEnc, data []byte, o lzmaOpts) ([]byte, []byte, error) {
	out, err := enc.encode(ctx, data, o)
	if err != nil {
		return nil, nil, err
	}
	if len(out) < 13 {
		return nil, nil, fmt.Errorf("sevenz: short LZMA stream")
	}
	return out[13:], append([]byte(nil), out[:5]...), nil
}

// EncodedHeader is the uncompressed kHeader used for tests and wrap rebuilds.
func EncodedHeader(files []File, packSizes, unpackSizes []uint64, crcs []uint32, props [][]byte) []byte {
	return encodeHeader(files, packSizes, unpackSizes, crcs, props)
}

func encodeHeader(files []File, packSizes, unpackSizes []uint64, crcs []uint32, props [][]byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x01) // kHeader
	b.WriteByte(0x04) // kMainStreamsInfo
	b.WriteByte(0x06) // kPackInfo
	writeNumber(&b, 0)
	writeNumber(&b, uint64(len(files)))
	b.WriteByte(0x09)
	for _, n := range packSizes {
		writeNumber(&b, n)
	}
	b.WriteByte(0x00)
	b.WriteByte(0x07) // kUnpackInfo
	b.WriteByte(0x0b)
	writeNumber(&b, uint64(len(files)))
	b.WriteByte(0)
	for i := range files {
		b.WriteByte(1)
		b.WriteByte(0x23)
		b.Write([]byte{3, 1, 1})
		writeNumber(&b, uint64(len(props[i])))
		b.Write(props[i])
	}
	b.WriteByte(0x0c)
	for _, n := range unpackSizes {
		writeNumber(&b, n)
	}
	b.WriteByte(0x00) // kEnd unpack — CRC lives in SubStreamsInfo
	b.WriteByte(0x08) // kSubStreamsInfo
	b.WriteByte(0x0a)
	b.WriteByte(1)
	for _, c := range crcs {
		binary.Write(&b, binary.LittleEndian, c)
	}
	b.WriteByte(0x00)
	b.WriteByte(0x00) // kEnd streams
	b.WriteByte(0x05) // kFilesInfo
	writeNumber(&b, uint64(len(files)))
	var names bytes.Buffer
	for _, f := range files {
		for _, r := range f.Name {
			var u [2]byte
			binary.LittleEndian.PutUint16(u[:], uint16(r))
			names.Write(u[:])
		}
		names.Write([]byte{0, 0})
	}
	nameSize := uint64(names.Len() + 1)
	skipToAligned(&b, 2+numberSize(nameSize), 4)
	b.WriteByte(0x11) // kName
	writeNumber(&b, nameSize)
	b.WriteByte(0)
	b.Write(names.Bytes())
	attrSize := uint64(4*len(files) + 2)
	skipToAligned(&b, 3+numberSize(attrSize), 2)
	b.WriteByte(0x15) // kWinAttrib
	writeNumber(&b, attrSize)
	b.WriteByte(1)
	b.WriteByte(0)
	for range files {
		binary.Write(&b, binary.LittleEndian, uint32(winArchive))
	}
	b.WriteByte(0x00)
	b.WriteByte(0x00)
	return b.Bytes()
}

func skipToAligned(b *bytes.Buffer, prefix int, alignShifts int) {
	align := 1 << alignShifts
	pos := (prefix + b.Len()) & (align - 1)
	if pos == 0 {
		return
	}
	skip := align - pos
	if skip < 2 {
		skip += align
	}
	skip -= 2
	b.WriteByte(0x19) // kDummy
	b.WriteByte(byte(skip))
	b.Write(make([]byte, skip))
}

func numberSize(v uint64) int {
	var b bytes.Buffer
	writeNumber(&b, v)
	return b.Len()
}

func writeNumber(b *bytes.Buffer, v uint64) {
	var first, mask byte = 0, 0x80
	i := 0
	for ; i < 8; i++ {
		if v < uint64(1)<<(7*(i+1)) {
			first |= byte(v >> (8 * i))
			break
		}
		first |= mask
		mask >>= 1
	}
	b.WriteByte(first)
	for ; i > 0; i-- {
		b.WriteByte(byte(v))
		v >>= 8
	}
}
