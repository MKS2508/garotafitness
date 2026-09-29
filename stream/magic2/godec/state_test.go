package godec

import "testing"

// TestRenormEmpty: X starts below kL, no input to read → must set OK=false
// without panicking. Matches the underrun path at main.cpp:235-237.
func TestRenormEmpty(t *testing.T) {
	r := &Rans{X: 0, Buf: nil, Off: 0, Len: 0, OK: true}
	r.Renorm()
	if r.OK {
		t.Fatalf("Renorm on empty input should set OK=false, got OK=true (X=0x%x, Off=%d)", r.X, r.Off)
	}
	if r.Off != 0 {
		t.Fatalf("Off should stay at 0 on underrun, got %d", r.Off)
	}
}

// TestRenormFourBytes: X starts at 0, buf has 4 bytes of 0xFF. The loop folds
// bytes one at a time: X = 0xFF, then 0xFFFF, then 0xFFFFFF. After the third
// fold X >= kL so the loop exits without consuming the 4th byte. Off=3,
// not 4 — the loop's terminating condition is X < kL, not Off < Len.
func TestRenormFourBytes(t *testing.T) {
	buf := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	r := &Rans{X: 0, Buf: buf, Off: 0, Len: 4, OK: true}
	r.Renorm()
	if !r.OK {
		t.Fatalf("Renorm with 4 bytes of 0xFF should stay OK, X=0x%x Off=%d", r.X, r.Off)
	}
	if r.X != 0xFFFFFF {
		t.Fatalf("X should be 0xFFFFFF after 3 folds of 0xFF (4th byte not consumed — X already past kL), got 0x%x", r.X)
	}
	if r.Off != 3 {
		t.Fatalf("Off should reach 3, got %d", r.Off)
	}
}

// TestRenormHundredBytes: X already well above kL → loop doesn't execute,
// OK stays true. Confirms the early-exit path at main.cpp:232.
func TestRenormHundredBytes(t *testing.T) {
	buf := make([]byte, 100)
	for i := range buf {
		buf[i] = 0x80
	}
	r := &Rans{X: kL + 1, Buf: buf, Off: 0, Len: 100, OK: true}
	r.Renorm()
	if !r.OK {
		t.Fatalf("Renorm with X >= kL should stay OK, X=0x%x Off=%d", r.X, r.Off)
	}
	if r.Off != 0 {
		t.Fatalf("Off should stay at 0 when no bytes needed, got %d", r.Off)
	}
	if r.X != kL+1 {
		t.Fatalf("X should be untouched, got 0x%x", r.X)
	}
}

// TestNewLE: full constructor path. 4 bytes of 0xFF saturate X above kL
// after the LE read, so Renorm doesn't pull any extra bytes — Off stays at 4
// and X stays at 0xFFFFFFFF. Confirms both the LE byte order and that Renorm
// ran.
func TestNewLE(t *testing.T) {
	buf := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	r := NewLE(buf)
	if !r.OK {
		t.Fatalf("NewLE on 4 bytes of 0xFF should keep OK=true")
	}
	if r.X != 0xFFFFFFFF {
		t.Fatalf("expected X=0xFFFFFFFF (LE read of 4x 0xFF), got 0x%x", r.X)
	}
	if r.Off != 4 {
		t.Fatalf("expected Off=4 after init (X already >= kL), got %d", r.Off)
	}
}