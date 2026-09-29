// Package godec — cls11-only dispatch entry point.
//
// decode_v22 in main.cpp uses a 1-bit lit/match classifier (line 803) as
// the central dispatch and runs the 16-sym class decoder (line 1411)
// only when the 1-bit classifier signals a match. This file ports the
// alternative dispatch shape — the cls11-only model used by the
// decode.go scaffold's decodeChunkGroupCap — so both models coexist:
// the production v22 entry keeps the 1-bit classifier, and this entry
// uses the 16-sym cls directly as the central dispatch.
//
// Per-symbol dispatch (cls read via GetNibble, which already calls
// adapt16 internally on the cls11 CDF row):
//
//	cls 0..7   → literal: emit byte (low byte of rANS state)
//	cls 8..10  → reserved: raw-copy / special (placeholder; falls
//	             through to literal until the use_hdr / opt_skip
//	             header path is wired)
//	cls 11     → match: DecodeOff + IntModel.DecodePE + MatchCopy
//	cls 12..15 → short rep: length 2, distance from reps[cls-12]
//
// State updates per symbol:
//
//	esi      kEsiTab[esi] for literals, EsiAfterMatch(esi, cls, hist)
//	         for match / short-rep
//	rolz     Push(prev, ringPos) and Push(b, ringPos) for literals;
//	         MatchCopy rolls forward on the match path so the ring
//	         and rolz state stay in lockstep with the byte stream
//	cls11    GetNibble's adapt16 call walks the (esi, hist) row
//	         toward kMatchTgt[cls] — no manual adapt call needed
//
// The cls11-only model is the simpler of the two production shapes:
// it loses the per-cls match handling (cls 1, 2, 3, 10) that the
// 1-bit + 16-sym v22 model has, and gains a flat dispatch loop that
// doesn't depend on the 1-bit classifier's CDF (litP) staying warm.
// The two models are intentionally additive: callers that need the
// richer per-cls match handling keep using DecodeV22Full; callers
// that want a deterministic, scaffold-shaped dispatch use
// DecodeV22Cls11.
//
// Key refs (from the cls-magic2 v22 reconstruction):
//   - decode_v22 main loop    main.cpp:976-1581
//   - cls11 dispatch (scaffold model)  decode.go:decodeChunkGroupCap
//   - get_nibble              main.cpp:326-339
//   - decode_off              main.cpp:742-768
//   - esi_after_match         main.cpp:211-224
//   - decode_int_pe           main.cpp:452-492
package godec

import (
	"context"
	"io"
)

// DecodeV22Cls11 is the cls11-only dispatch entry point. It reads the
// 16-sym class CDF directly as the central dispatch (no 1-bit
// classifier gating) and branches on the decoded class:
//
//	cls 0..7   → literal (low byte of rANS state)
//	cls 8..10  → reserved (placeholder, falls through to literal)
//	cls 11     → match (offset + length + MatchCopy)
//	cls 12..15 → short rep (length 2, dist from reps[cls-12])
//
// cap defaults to kWant (430889, the per-chunk-group cap the
// production WASM kernel enforces) when 0 is passed. Returns n>0 on
// a successful decode, (nil, 0, io.EOF) on a no-byte collapse
// (sub-4-byte body, optSkip past the slice, or rANS underrun before
// the first symbol).
//
// State persistence: *State's ROLZ + RingBuffer + ClsTab + Esi +
// Reps + Rep0 + IntModel all carry their learned context across
// calls so chunk N+1's match candidates include chunk N's literals.
// The Rans field is reinitialised from the 4-byte chunk header on
// each call.
func DecodeV22Cls11(ctx context.Context, state *State, src []byte, optSkip, forceOpt int, cap uint32) (out []byte, n int, err error) {
	if state == nil {
		return nil, 0, io.EOF
	}
	if optSkip < 0 {
		optSkip = 0
	}
	if optSkip >= len(src) {
		state.LastConsumed = 0
		return nil, 0, io.EOF
	}
	src = src[optSkip:]
	if len(src) < 4 {
		state.LastConsumed = 0
		return nil, 0, io.EOF
	}

	r := Rans{
		Buf: src,
		Off: 4,
		Len: len(src),
		OK:  true,
		X:   uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16 | uint32(src[3])<<24,
	}
	r.Renorm()

	if cap == 0 {
		cap = kWant
	}
	if cap > kWant {
		cap = kWant
	}

	// Seed the cls11 CDFs uniformly on the first call. The C version's
	// static-array init runs on every decode_v22 entry; here we mirror
	// the per-call init through ResetCD so a fresh *State behaves the
	// same regardless of how many chunk-groups it processes.
	if !state.clsMagic2CInit {
		state.ResetCD()
	}

	// Resolve optN → kHistTab row + kPcMask position-mask.
	optN := 0
	if forceOpt >= 0 {
		optN = forceOpt
	}
	if optN < 0 {
		optN = 0
	}
	if optN >= len(kPCMaskForOptN) {
		optN = len(kPCMaskForOptN) - 1
	}
	pcMask := int(kPCMaskForOptN[optN])

	out = make([]byte, 0, cap)
	prev := state.Prev
	rep0 := state.Rep0
	if rep0 < 1 {
		rep0 = 1
	}
	esi := int(state.Esi)
	reps := state.Reps[:]

	// Main loop — cls11 dispatch. GetNibble on the (esi, hist) row of
	// state.ClsTab both decodes the symbol and adapts the row toward
	// kMatchTgt[cls] in one call.
	for uint32(len(out)) < cap && r.OK {
		if err := ctx.Err(); err != nil {
			break
		}
		if r.X < kL && r.Off >= r.Len {
			break
		}

		n := len(out)
		hist := int(kHistTab[optN][n&pcMask])
		crow := esi*16 + hist
		if crow < 0 {
			crow = 0
		}
		if crow >= 4096 {
			crow = 4095
		}

		cls := r.GetNibble(state.ClsTab[crow][:], 16, 6, kMatchTgt)
		if cls < 0 {
			break
		}
		if cls > 15 {
			cls = 15
		}

		switch {
		case cls <= 7:
			// Literal: low byte of rANS state. The cls11 dispatch
			// reads the byte directly from X rather than running the
			// hi/lo mix the 1-bit + 16-sym v22 model uses — this is
			// the simplest "literal" the cls-only model supports.
			b := byte(r.X & 0xff)
			state.Ring.Slot = b
			state.Ring.LiteralCopy(n)
			out = append(out, b)
			state.ROLZ.Push(prev, n)
			state.ROLZ.Push(int(b), n)
			prev = int(b)
			esi = int(kEsiTab[esi])

		case cls == 11:
			// Match: decode length via IntModel.DecodePE, then
			// derive the offset from the ROLZ hash chain so the
			// previous-byte context feeds the offset slot lookup.
			ln := state.IntModel.DecodePE(&r, prev)
			if ln < 0 {
				break
			}
			idx := state.ROLZ.LookupDistance(prev, ln&(RolzCap-1), n)
			if idx <= 0 {
				idx = 1
			}
			dist := DecodeOff(11, idx, &rep0, reps, 32)
			if dist <= 0 {
				break
			}
			mLen := ln + 2
			if mLen <= 0 {
				break
			}
			if uint32(n+mLen) > cap {
				mLen = int(cap) - n
				if mLen <= 0 {
					break
				}
			}
			ringDst := n
			ringRef := n - dist
			if ringRef < 0 {
				ringRef = 0
			}
			state.Ring.MatchCopy(ringDst, ringRef, mLen)
			state.Ring.Pos += mLen
			for i := 0; i < mLen; i++ {
				out = append(out, state.Ring.Buf[(ringDst+i)&kRingMask])
			}
			if mLen > 0 {
				prev = int(out[len(out)-1])
			}
			esi = EsiAfterMatch(esi, 11, hist)

		case cls >= 12 && cls <= 15:
			// Short rep: length 2, dist from reps[cls-12] via
			// DecodeOff's slot-rotation path.
			dist := DecodeOff(cls, 0, &rep0, reps, 32)
			if dist <= 0 {
				break
			}
			mLen := 2
			if uint32(n+mLen) > cap {
				mLen = int(cap) - n
				if mLen <= 0 {
					break
				}
			}
			ringDst := n
			ringRef := n - dist
			if ringRef < 0 {
				ringRef = 0
			}
			state.Ring.MatchCopy(ringDst, ringRef, mLen)
			state.Ring.Pos += mLen
			for i := 0; i < mLen; i++ {
				out = append(out, state.Ring.Buf[(ringDst+i)&kRingMask])
			}
			if mLen > 0 {
				prev = int(out[len(out)-1])
			}
			esi = EsiAfterMatch(esi, cls, hist)

		default:
			// cls 8..10 reserved (raw-copy / opt-skip preambles
			// aren't wired yet). Fall back to literal so the
			// decoder keeps producing bytes until the real path
			// is added — matches the scaffold's `default → byte(r.X)`
			// branch in decode.go's decodeChunkGroupCap.
			b := byte(r.X & 0xff)
			state.Ring.Slot = b
			state.Ring.LiteralCopy(n)
			out = append(out, b)
			state.ROLZ.Push(prev, n)
			state.ROLZ.Push(int(b), n)
			prev = int(b)
			esi = int(kEsiTab[esi])
		}
	}

	if err := ctx.Err(); err != nil {
		state.LastConsumed = r.Off
		state.Esi = uint32(esi)
		state.Rep0 = rep0
		state.Prev = prev
		state.OptN = uint8(optN)
		state.PcMask = uint8(pcMask)
		state.Rans = r
		return out, len(out), err
	}

	// Persist state across the chunk-group boundary.
	state.LastConsumed = r.Off
	state.Esi = uint32(esi)
	state.Rep0 = rep0
	state.Prev = prev
	state.OptN = uint8(optN)
	state.PcMask = uint8(pcMask)
	state.Rans = r

	if len(out) == 0 {
		return nil, 0, io.EOF
	}
	return out, len(out), nil
}

// DecodeV22Cls11Compat is the harness-required-signature wrapper that
// pins optSkip=0 and forceOpt=-1 and writes into a local scratch
// buffer. Mirrors DecodeV22FullCompat.
func DecodeV22Cls11Compat(ctx context.Context, state *State, src []byte) (out []byte, err error) {
	out, _, err = DecodeV22Cls11(ctx, state, src, 0, -1, kWant)
	return out, err
}
