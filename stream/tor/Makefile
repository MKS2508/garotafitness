# Official Tornado decompress guest.
EMCC ?= emcc
ARC = ../../third_party/freearc/Compression
GUEST = tordec.wasm
SRC = guest/main.cpp $(ARC)/Common.cpp

include ../../make/committed-wasm.mk

$(GUEST): $(SRC) $(ARC)/Tornado/Tornado.cpp
	$(EMCC) $(SRC) \
		-O0 -std=c++17 -fno-exceptions -fno-rtti -Wno-c++11-narrowing -Wno-format-zero-length \
		-DFREEARC_UNIX -DFREEARC_INTEL_BYTE_ORDER -DFREEARC_DECOMPRESS_ONLY \
		-I$(ARC) -I$(ARC)/Tornado \
		--no-entry \
		-sSTANDALONE_WASM=1 \
		-sALLOW_MEMORY_GROWTH=1 \
		-sINITIAL_MEMORY=67108864 \
		-sMAXIMUM_MEMORY=2147483648 \
		-sSTACK_SIZE=2097152 \
		-sEXPORTED_FUNCTIONS=_tor_decode,_malloc,_free \
		-Wno-version-check \
		-o $(GUEST)

clean:
	rm -f $(GUEST)
