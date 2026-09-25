EMCC ?= emcc
SRC = ../../third_party/xdelta3
GUEST = xdelta.wasm
include ../../make/committed-wasm.mk

xdelta.wasm: guest/main.c guest/stream.c $(SRC)/xdelta3.c $(wildcard $(SRC)/*.h)
	$(EMCC) -O1 -std=gnu11 --no-entry -I$(SRC) guest/main.c guest/stream.c $(SRC)/xdelta3.c \
		-DXD3_ENCODER=0 -DSECONDARY_LZMA=0 -DXD3_USE_LARGESIZET=0 \
		-DSIZEOF_SIZE_T=4 -DSIZEOF_UNSIGNED_INT=4 -DSIZEOF_UNSIGNED_LONG=4 -DSIZEOF_UNSIGNED_LONG_LONG=8 \
		-sSTANDALONE_WASM=1 -sALLOW_MEMORY_GROWTH=1 \
		-sINITIAL_MEMORY=67108864 -sMAXIMUM_MEMORY=2147483648 -sSTACK_SIZE=1048576 \
		-sEXPORTED_FUNCTIONS=_xdelta_apply,_xdelta_apply_stream,_malloc,_free \
		-sERROR_ON_UNDEFINED_SYMBOLS=0 -Wno-version-check -o $@
