# Hybrid SREP Guest: official Future-LZ kernel, no pthreads.
# -O0: conda binaryen 117 rejects emcc 4.0.9 wasm-opt flags (same as gameweb).
EMCC ?= emcc
GUEST = srepdec.wasm
SRC = guest/main.cpp

include ../../make/committed-wasm.mk

$(GUEST): $(SRC) guest/kernel.h
	$(EMCC) $(SRC) \
		-O0 -std=c++17 -fno-exceptions -fno-rtti \
		-Iguest \
		--no-entry \
		-sSTANDALONE_WASM=1 \
		-sALLOW_MEMORY_GROWTH=1 \
		-sINITIAL_MEMORY=67108864 \
		-sMAXIMUM_MEMORY=2147483648 \
		-sSTACK_SIZE=1048576 \
		-sEXPORTED_FUNCTIONS=_srep_open,_srep_block,_srep_close,_malloc,_free \
		-Wno-version-check \
		-o $(GUEST)
