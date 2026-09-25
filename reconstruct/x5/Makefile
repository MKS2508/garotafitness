EMCC ?= emcc
SRC = ../../third_party/hdiffpatch
GUEST = hpatch.wasm
include ../../make/committed-wasm.mk

hpatch.wasm: guest/main.c $(wildcard $(SRC)/*.[ch])
	$(EMCC) -O0 -std=gnu11 --no-entry -I$(SRC) guest/main.c $(SRC)/patch.c \
		-sSTANDALONE_WASM=1 -sALLOW_MEMORY_GROWTH=1 \
		-sINITIAL_MEMORY=67108864 -sMAXIMUM_MEMORY=2147483648 -sSTACK_SIZE=1048576 \
		-sEXPORTED_FUNCTIONS=_hpatch_size,_hpatch_apply,_malloc,_free \
		-Wno-version-check -o $@
