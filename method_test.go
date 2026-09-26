package garotafitness

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePipeline(t *testing.T) {
	t.Parallel()
	p := ParsePipeline("mpzz+srep:m3f:mem228mb")
	require.Equal(t, "mpzz+srep:m3f:mem228mb", p.String())
	require.Len(t, p, 2)
	require.Equal(t, AlgoMPZZ, p[0].Algo)
	require.Equal(t, AlgoSREP, p[1].Algo)
	require.Equal(t, "m3f:mem228mb", p[1].Params)
	require.Equal(t, AlgoSREP, p.Last().Algo)
}

func TestParseAlgoAliases(t *testing.T) {
	t.Parallel()
	require.Equal(t, AlgoDispack, ParseAlgo("dispack070"))
	require.Equal(t, AlgoRZW, ParseAlgo("rzwb"))
	require.Equal(t, AlgoRZS, ParseAlgo("rzs"))
	require.Equal(t, AlgoPref, ParseAlgo("pref"))
	require.Equal(t, AlgoXT3U, ParseAlgo("xt3u"))
	require.Equal(t, AlgoXT2PNG, ParseAlgo("xt2png"))
	require.Equal(t, AlgoTOR, ParseAlgo("tor"))
	require.False(t, ParseAlgo("nope").Known())
}
