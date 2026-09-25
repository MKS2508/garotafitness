package mpzz

import "testing"

func TestMarshalSplit255Laces(t *testing.T) {
	h := pageHeader{flags: 0, granule: 1, serial: 2, sequence: 3}
	// 200 packets of 300 bytes = 400 laces (255+45 each).
	body := make([]byte, 200*300)
	for i := 0; i < 200; i++ {
		h.packets = append(h.packets, 300)
		h.lacing = append(h.lacing, 255, 45)
	}
	out, err := h.marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	pages, off := 0, 0
	for off < len(out) {
		if string(out[off:off+4]) != "OggS" {
			t.Fatalf("page %d at %d", pages, off)
		}
		nseg := int(out[off+26])
		if nseg == 0 || nseg > 255 {
			t.Fatalf("nseg %d", nseg)
		}
		size := 27 + nseg
		for _, s := range out[off+27 : off+27+nseg] {
			size += int(s)
		}
		off += size
		pages++
	}
	if pages < 2 {
		t.Fatalf("pages %d; want split", pages)
	}
}
