package garotafitness

import "strings"

// Algo is one decompressor atom. Zero is invalid.
type Algo uint8

const (
	AlgoInvalid Algo = iota
	AlgoStoring
	AlgoLZMA
	AlgoLZMA2
	AlgoSREP
	Algo4x4
	AlgoRZW
	AlgoRZS
	AlgoMagic2
	AlgoMPZZ
	AlgoMPZ
	AlgoDispack
	AlgoDelta
	AlgoREP
	AlgoPPMD
	AlgoPref
	AlgoXT3U
	AlgoXT2PNG
	AlgoTOR
)

var algoName = [...]string{
	AlgoInvalid: "invalid",
	AlgoStoring: "storing",
	AlgoLZMA:    "lzma",
	AlgoLZMA2:   "lzma2",
	AlgoSREP:    "srep",
	Algo4x4:     "4x4",
	AlgoRZW:     "rzw",
	AlgoRZS:     "rzs",
	AlgoMagic2:  "magic2",
	AlgoMPZZ:    "mpzz",
	AlgoMPZ:     "mpz",
	AlgoDispack: "dispack",
	AlgoDelta:   "delta",
	AlgoREP:     "rep",
	AlgoPPMD:    "ppmd",
	AlgoPref:    "pref",
	AlgoXT3U:    "xt3u",
	AlgoXT2PNG:  "xt2png",
	AlgoTOR:     "tor",
}

var algoByName = map[string]Algo{
	"storing":    AlgoStoring,
	"lzma":       AlgoLZMA,
	"lzma2":      AlgoLZMA2,
	"srep":       AlgoSREP,
	"4x4":        Algo4x4,
	"rzw":        AlgoRZW,
	"rzwb":       AlgoRZW,
	"rzs":        AlgoRZS,
	"magic2":     AlgoMagic2,
	"mpzz":       AlgoMPZZ,
	"mpz":        AlgoMPZ,
	"dispack":    AlgoDispack,
	"dispack070": AlgoDispack,
	"delta":      AlgoDelta,
	"rep":        AlgoREP,
	"ppmd":       AlgoPPMD,
	"pref":       AlgoPref,
	"xt3u":       AlgoXT3U,
	"xt2png":     AlgoXT2PNG,
	"tor":        AlgoTOR,
}

// String returns the canonical on-disk name.
func (a Algo) String() string {
	if int(a) >= len(algoName) {
		return algoName[AlgoInvalid]
	}
	return algoName[a]
}

// Known reports whether a is a defined atom.
func (a Algo) Known() bool {
	return a != AlgoInvalid && int(a) < len(algoName)
}

// ParseAlgo maps a FreeArc method name (no params) to an Algo.
func ParseAlgo(name string) Algo {
	if a, ok := algoByName[strings.ToLower(name)]; ok {
		return a
	}
	return AlgoInvalid
}
