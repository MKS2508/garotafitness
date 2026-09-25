// Package x4 rebuilds Giants Engine .dlc/.gar packs used by the installer.
package x4

import (
	"bytes"
	"fmt"
	"io"
	"sort"
)

// File is one member of a packed directory.
type File struct {
	Name string
	Data []byte
}

// keys for x4.exe DIR OUT 02 <minor>, minor is parsed as hex and must be < 3.
// From the PE table at VA 0x414ef8 (same values as aluigi giants_software.bms ENC_MODE 2).
var keys = [3][4]uint32{
	{0x022DBB1E, 0x22EC2A94, 0x1B0C37E7, 0x2501A594},
	{0x23F0EA64, 0x317FAC94, 0x1B0C37E7, 0x2501A594},
	{0x30D0D6B6, 0x14B281C4, 0x2F28AC14, 0x29F53CB9},
}

// Pack writes the directory the way the official x4.exe stub does:
// sort paths, pad each body to 8 bytes, encrypt with defarm, concatenate.
// `02 01` selects key row 1 (DLC); `02 02` selects row 2 (dataS.gar).
func Pack(files []File, major, minor string) ([]byte, error) {
	var buf bytes.Buffer
	if err := PackTo(&buf, files, major, minor); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PackTo encrypts each body and writes the concatenation to w without holding
// the whole pack in memory.
func PackTo(w io.Writer, files []File, major, minor string) error {
	key, err := Key(major, minor)
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	for _, f := range files {
		block := pad8(f.Data)
		defarm(block, key)
		if _, err := w.Write(block); err != nil {
			return err
		}
	}
	return nil
}

// Key is the 16-byte defarm key for x4.exe DIR OUT <major> <minor>.
func Key(major, minor string) ([4]uint32, error) {
	var z [4]uint32
	if major != "02" {
		return z, fmt.Errorf("x4: unsupported version %s %s", major, minor)
	}
	switch minor {
	case "01":
		return keys[1], nil
	case "02":
		return keys[2], nil
	default:
		return z, fmt.Errorf("x4: unsupported version %s %s", major, minor)
	}
}

// EncryptBody pads and encrypts one file for concatenation into a pack.
func EncryptBody(data []byte, key [4]uint32) []byte {
	block := pad8(data)
	defarm(block, key)
	return block
}

// defarm is the inner-DLL cipher: DES-variant Feistel, 34-block cycle, RC4 on even blocks.
func defarm(buf []byte, key [4]uint32) {
	c := newFarmCipher(key)
	c.encrypt(buf)
}
