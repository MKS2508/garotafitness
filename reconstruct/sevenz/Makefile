EMCC ?= emcc
SRC = ../../third_party/lzma-7zip2602
SOURCES = guest/main.c $(SRC)/LzmaEnc.c $(SRC)/LzFind.c $(SRC)/Alloc.c $(SRC)/CpuArch.c
GUEST = sevenzenc.wasm
include ../../make/committed-wasm.mk

sevenzenc.wasm: $(SOURCES) $(wildcard $(SRC)/*.h)
	$(EMCC) -O1 -std=gnu11 -DZ7_ST -D_POSIX_C_SOURCE=200112L --no-entry -I$(SRC) $(SOURCES) \
		-sSTANDALONE_WASM=1 -sALLOW_MEMORY_GROWTH=1 \
		-sINITIAL_MEMORY=67108864 -sMAXIMUM_MEMORY=2147483648 -sSTACK_SIZE=1048576 \
		-sEXPORTED_FUNCTIONS=_sevenz_lzma,_malloc,_free -Wno-version-check -o $@
