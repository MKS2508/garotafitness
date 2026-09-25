EMCC ?= emcc
SRC = ../../third_party/hdiffpatch4
GUEST = hpatchsf.wasm
include ../../make/committed-wasm.mk

hpatchsf.wasm: guest/main.c $(wildcard $(SRC)/*.[ch])
	$(EMCC) -O0 -std=gnu11 -D_FILE_OFFSET_BITS=64 --no-entry -I$(SRC) guest/main.c $(SRC)/patch.c \
		-sSTANDALONE_WASM=1 -sALLOW_MEMORY_GROWTH=1 \
		-sINITIAL_MEMORY=134217728 -sMAXIMUM_MEMORY=2147483648 -sSTACK_SIZE=1048576 \
		-sEXPORTED_FUNCTIONS=_hpatch_sf20,_malloc,_free \
		-sERROR_ON_UNDEFINED_SYMBOLS=0 -Wno-version-check -o $@
