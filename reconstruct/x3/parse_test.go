package x3

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func testRecordBytes() []byte {
	h := make([]byte, 40)
	copy(h, "K*")
	binary.LittleEndian.PutUint16(h[2:], 0x384)
	binary.LittleEndian.PutUint16(h[4:], 0x82e4)
	binary.LittleEndian.PutUint32(h[6:], 0x10000)
	binary.LittleEndian.PutUint16(h[10:], 0x288)
	binary.LittleEndian.PutUint32(h[32:], 1)
	var b bytes.Buffer
	b.Write(h)
	u16 := func(v uint16) { b.Write(binary.LittleEndian.AppendUint16(nil, v)) }
	u32 := func(v uint32) { b.Write(binary.LittleEndian.AppendUint32(nil, v)) }
	text := func(v string) { b.WriteByte(byte(len(v) + 1)); b.WriteString(v); b.WriteByte(0) }
	u16(2)
	text("DATA")
	text("Data")
	code := []byte{0x15, 0, 0x14, 0, 3, 0x11, 2, 1, 0x16}
	u16(0x4441)
	b.Write([]byte{0, 1})
	b.Write(make([]byte, 10))
	u16(9)
	b.Write([]byte{1, 1})
	u32(uint32(len(code)))
	u32(uint32(len(code)))
	for _, data := range []string{"abc", "abd"} {
		v := make([]byte, 24)
		binary.LittleEndian.PutUint32(v[16:], uint32(len(data)))
		b.Write(v)
		a, c := checksum([]byte(data))
		u16(0)
		u32(a)
		u32(c)
		b.Write(make([]byte, 8))
		text("\x9f.txt") // CP866 Я; differs from Windows-1251.
	}
	b.Write(code)
	u16(0x1000)
	return b.Bytes()
}

func TestParseAndApplyRecord(t *testing.T) {
	data := testRecordBytes()
	records, err := Parse(data)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, "Data/Я.txt", records[0].Source)
	require.Equal(t, "Data/Я.txt", records[0].Target)
	out, err := records[0].Apply(t.Context(), []byte("abc"))
	require.NoError(t, err)
	require.Equal(t, "abd", string(out))
	for n := range len(data) {
		_, err := Parse(data[:n])
		require.Error(t, err)
	}
	bad := bytes.Clone(data)
	binary.LittleEndian.PutUint32(bad[32:], 2)
	_, err = Parse(bad)
	require.Error(t, err)
	_, err = Parse(append(data, 0))
	require.Error(t, err)
	bad = bytes.Replace(data, []byte("\x9f.txt"), []byte("../xx"), 1)
	_, err = Parse(bad)
	require.Error(t, err)
}

func TestVariableIntegerBounds(t *testing.T) {
	for _, tt := range []struct {
		data []byte
		want int64
	}{
		{[]byte{0}, 0}, {[]byte{63}, 63}, {[]byte{0x81}, -1},
		{[]byte{0x40, 64}, 64}, {[]byte{0xc0, 64}, -64},
		{[]byte{0x78, 255, 255, 255, 255}, 0xffffffff},
	} {
		r := cursor{data: tt.data}
		got := r.vli()
		require.NoError(t, r.err)
		require.Equal(t, tt.want, got)
	}
	for _, data := range [][]byte{{0x7c}, {0x40}, {0x60, 0}} {
		r := cursor{data: data}
		r.vli()
		require.Error(t, r.err)
	}
}
