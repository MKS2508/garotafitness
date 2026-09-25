# Hybrid mpzz guest: reconstructed OGGRE kernel (INV-03: no PE exec).
# -O0: conda binaryen 117 rejects emcc 4.0.9 wasm-opt flags (same as srep).
EMCC ?= emcc
GUEST = mpzzdec.wasm
SRC = guest/kernel.cpp

.PHONY: guest
guest: $(GUEST)

$(GUEST): $(SRC)
	$(EMCC) $(SRC) \
		-O0 -std=c++17 -fno-exceptions -fno-rtti \
		--no-entry \
		-sSTANDALONE_WASM=1 \
		-sALLOW_MEMORY_GROWTH=1 \
		-sINITIAL_MEMORY=67108864 \
		-sMAXIMUM_MEMORY=2147483648 \
		-sSTACK_SIZE=16777216 \
		-sEXPORTED_FUNCTIONS=_mpzz_decode,_malloc,_free \
		-Wno-version-check \
		-o $(GUEST)
