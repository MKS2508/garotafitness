# LLVM optimizes the translation before linking. Linking at -O0 avoids the
# incompatible wasm-opt flags in the pinned conda emscripten/binaryen pair.
EMCC ?= emcc
GUEST = mpzdec.wasm
include ../../make/committed-wasm.mk
mpzdec.wasm: guest/decoder.c guest/mpz-native.h guest/mpz-entry.inc guest/mpz-tables.inc
	$(EMCC) guest/decoder.c -O2 -std=c11 -Wno-parentheses-equality -c -o decoder.o
	$(EMCC) decoder.o -O0 --no-entry -sSTANDALONE_WASM=1 \
		-sALLOW_MEMORY_GROWTH=1 -sINITIAL_MEMORY=67108864 \
		-sMAXIMUM_MEMORY=2147483648 -sSTACK_SIZE=2097152 \
		-sEXPORTED_FUNCTIONS=_mpz_decode,_malloc,_free -o $@
	rm -f decoder.o
