EMCC ?= emcc
SRC = ../../third_party/lzma-sdk19
SOURCES = guest/main.c $(SRC)/LzmaEnc.c $(SRC)/LzFind.c $(SRC)/Alloc.c
GUEST = fgpack.wasm
include ../../make/committed-wasm.mk

fgpack.wasm: $(SOURCES) $(wildcard $(SRC)/*.h)
	$(EMCC) -O1 -std=c11 -D_7ZIP_ST --no-entry -I$(SRC) $(SOURCES) \
		-sSTANDALONE_WASM=1 -sALLOW_MEMORY_GROWTH=1 \
		-sINITIAL_MEMORY=67108864 -sMAXIMUM_MEMORY=2147483648 -sSTACK_SIZE=1048576 \
		-sEXPORTED_FUNCTIONS=_fgpack_encode,_malloc,_free -Wno-version-check -o $@
