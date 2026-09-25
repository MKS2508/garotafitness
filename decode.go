package garotafitness

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/lucasew/garotafitness/stream/delta"
	"github.com/lucasew/garotafitness/stream/dispack"
	"github.com/lucasew/garotafitness/stream/fourx4"
	"github.com/lucasew/garotafitness/stream/lzma"
	"github.com/lucasew/garotafitness/stream/magic2"
	"github.com/lucasew/garotafitness/stream/mpz"
	"github.com/lucasew/garotafitness/stream/mpzz"
	"github.com/lucasew/garotafitness/stream/pref"
	"github.com/lucasew/garotafitness/stream/rzs"
	"github.com/lucasew/garotafitness/stream/rzw"
	"github.com/lucasew/garotafitness/stream/srep"
	"github.com/lucasew/garotafitness/stream/storing"
	"github.com/lucasew/garotafitness/stream/tor"
	"github.com/lucasew/garotafitness/stream/xt2png"
	"github.com/lucasew/garotafitness/stream/xt3u"
)

// Decode wraps r with the atom's decompressor.
// The root package owns this switch. Child packages must not import
// it. 4x4 takes a func(io.Reader, name, params string) instead.
func Decode(ctx context.Context, r io.Reader, a Atom) (io.ReadCloser, error) {
	out, err := decodeAtom(ctx, r, a)
	if err != nil {
		return nil, annotateAtom(a, err)
	}
	return namedDecoder{ReadCloser: out, atom: a}, nil
}

type namedDecoder struct {
	io.ReadCloser
	atom Atom
}

func (n namedDecoder) Read(p []byte) (int, error) {
	k, err := n.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		return k, annotateAtom(n.atom, err)
	}
	return k, err
}

func annotateAtom(a Atom, err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	name := a.String()
	if strings.HasPrefix(msg, name+":") || strings.HasPrefix(msg, a.Algo.String()+":") {
		return err
	}
	return fmt.Errorf("%s: %w", a, err)
}

func decodeAtom(ctx context.Context, r io.Reader, a Atom) (io.ReadCloser, error) {
	switch a.Algo {
	case Algo4x4:
		return fourx4.NewReader(ctx, r, a.Params, decodeInner)
	case AlgoSREP:
		return srep.NewReader(ctx, r)
	case AlgoLZMA:
		return lzma.NewReader(r)
	case AlgoStoring:
		return storing.NewReader(r)
	case AlgoDelta:
		return delta.NewReader(r)
	case AlgoDispack:
		return dispack.NewReader(r)
	case AlgoMPZZ:
		return mpzz.NewReader(ctx, r)
	case AlgoMPZ:
		return mpz.NewReader(ctx, r)
	case AlgoRZW:
		return rzw.NewReader(r)
	case AlgoRZS:
		return rzs.NewReader(r)
	case AlgoMagic2:
		return magic2.NewReader(r)
	case AlgoPref:
		return pref.NewReader(ctx, r)
	case AlgoXT3U:
		return xt3u.NewReader(ctx, r)
	case AlgoXT2PNG:
		return xt2png.NewReader(ctx, r)
	case AlgoTOR:
		return tor.NewReader(ctx, r)
	default:
		return nil, unknownEncoderError(a)
	}
}

func decodeInner(ctx context.Context, r io.Reader, name, params string) (io.ReadCloser, error) {
	return Decode(ctx, r, Atom{Algo: ParseAlgo(name), Params: params})
}
