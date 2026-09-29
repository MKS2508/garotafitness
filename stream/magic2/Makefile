# Hybrid magic2 guest: PE-reconstructed lolz v22c4b kernel.
# Official cls-magic2 is PE-only (INV-03: never execute it).
# -O0: conda binaryen 117 rejects emcc 4.0.9 wasm-opt flags (same as srep).
EMCC ?= emcc
GUEST = magic2dec.wasm
SRC = guest/main.cpp

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
		-sSTACK_SIZE=1048576 \
		-sEXPORTED_FUNCTIONS=_magic2_decode,_magic2_get_input_consumed,_malloc,_free \
		-Wno-version-check \
		-o $(GUEST)
