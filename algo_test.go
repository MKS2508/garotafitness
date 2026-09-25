package garotafitness

import "testing"

func TestParseAlgo(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want Algo
	}{
		{"storing", AlgoStoring},
		{"LZMA", AlgoLZMA},
		{"srep", AlgoSREP},
		{"4x4", Algo4x4},
		{"magic2", AlgoMagic2},
		{"mpzz", AlgoMPZZ},
		{"dispack070", AlgoDispack},
		{"rzwb", AlgoRZW},
		{"rzs", AlgoRZS},
		{"pref", AlgoPref},
		{"xt3u", AlgoXT3U},
		{"xt2png", AlgoXT2PNG},
		{"tor", AlgoTOR},
		{"x2", AlgoInvalid},
		{"fgpack", AlgoInvalid},
		{"nope", AlgoInvalid},
		{"", AlgoInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got := ParseAlgo(tc.in)
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestAlgoZeroInvalid(t *testing.T) {
	t.Parallel()
	var a Algo
	if a.Known() || a != AlgoInvalid {
		t.Fatalf("zero value %v", a)
	}
}
