EMCC ?= emcc
SRC = ../../third_party/oggvorbis2fsb5
SOURCES = $(SRC)/oggvorbis2fsb5.c $(wildcard $(SRC)/ogg/src/*.c) $(wildcard $(SRC)/vorbis/lib/*.c)
GUEST = fsb.wasm
include ../../make/committed-wasm.mk

# Match the project's emscripten/binaryen combination; see stream/srep/Makefile.
fsb.wasm: $(SOURCES) $(wildcard $(SRC)/vorbis/lib/*.h $(SRC)/vorbis/include/vorbis/*.h $(SRC)/ogg/src/*.h $(SRC)/ogg/include/ogg/*.h $(SRC)/include/*.h)
	$(EMCC) -O0 -std=c11 -include alloca.h \
		-I$(SRC)/include -I$(SRC)/ogg/include -I$(SRC)/vorbis/include $(SOURCES) \
		-sSTANDALONE_WASM=1 -sALLOW_MEMORY_GROWTH=1 \
		-sINITIAL_MEMORY=67108864 -sMAXIMUM_MEMORY=2147483648 -sSTACK_SIZE=1048576 \
		-Wno-version-check -lm -o $@
