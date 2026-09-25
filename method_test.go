package garotafitness

import (
	"testing"
)

func TestParsePipeline(t *testing.T) {
	t.Parallel()
	p := ParsePipeline("mpzz+srep:m3f:mem228mb")
	if p.String() != "mpzz+srep:m3f:mem228mb" {
		t.Fatalf("got %q", p.String())
	}
	if len(p) != 2 || p[0].Algo != AlgoMPZZ || p[1].Algo != AlgoSREP {
		t.Fatalf("got %+v", p)
	}
	if p[1].Params != "m3f:mem228mb" {
		t.Fatalf("params %q", p[1].Params)
	}
	if p.Last().Algo != AlgoSREP {
		t.Fatal(p.Last())
	}
}

func TestParseAlgoAliases(t *testing.T) {
	t.Parallel()
	if ParseAlgo("dispack070") != AlgoDispack {
		t.Fatal("dispack")
	}
	if ParseAlgo("rzwb") != AlgoRZW {
		t.Fatal("rzw")
	}
	if ParseAlgo("rzs") != AlgoRZS {
		t.Fatal("rzs")
	}
	if ParseAlgo("pref") != AlgoPref {
		t.Fatal("pref")
	}
	if ParseAlgo("xt3u") != AlgoXT3U {
		t.Fatal("xt3u")
	}
	if ParseAlgo("xt2png") != AlgoXT2PNG {
		t.Fatal("xt2png")
	}
	if ParseAlgo("tor") != AlgoTOR {
		t.Fatal("tor")
	}
	if ParseAlgo("nope").Known() {
		t.Fatal("want invalid")
	}
}
