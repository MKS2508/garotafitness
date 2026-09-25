# Official preflate restore guest. -O0: conda binaryen 117 rejects emcc 4.0.9 wasm-opt.
EMCC ?= emcc
PRECOMP = ../../third_party/precomp
GUEST = xt2pngdec.wasm
PREFLATE_STAGED = build/preflate
PREFLATE_NAMES = preflate_block_decoder.cpp preflate_block_reencoder.cpp preflate_block_trees.cpp \
	preflate_complevel_estimator.cpp preflate_constants.cpp preflate_decoder.cpp \
	preflate_hash_chain.cpp preflate_info.cpp preflate_parameter_estimator.cpp \
	preflate_parser_config.cpp preflate_predictor_state.cpp preflate_reencoder.cpp \
	preflate_seq_chain.cpp preflate_statistical_codec.cpp preflate_statistical_model.cpp \
	preflate_token.cpp preflate_token_predictor.cpp preflate_tree_predictor.cpp
PREFLATE_SUPPORT = arithmetic_coder.cpp array_helper.cpp bit_helper.cpp bitstream.cpp \
	const_division.cpp filestream.cpp huffman_decoder.cpp huffman_encoder.cpp \
	huffman_helper.cpp memstream.cpp outputcachestream.cpp
PREFLATE_SRC = $(addprefix $(PREFLATE_STAGED)/,$(PREFLATE_NAMES)) \
	$(addprefix $(PREFLATE_STAGED)/support/,$(PREFLATE_SUPPORT))
SRC = guest/main.cpp guest/task_pool.cpp $(PREFLATE_SRC)

include ../../make/committed-wasm.mk

$(PREFLATE_STAGED)/.stamp: guest/support/task_pool.h
	mkdir -p $(PREFLATE_STAGED)/support
	cp $(PRECOMP)/contrib/preflate/*.cpp $(PRECOMP)/contrib/preflate/*.h $(PREFLATE_STAGED)/
	cp $(PRECOMP)/contrib/preflate/support/* $(PREFLATE_STAGED)/support/
	cp guest/support/task_pool.h $(PREFLATE_STAGED)/support/task_pool.h
	touch $@

$(PREFLATE_SRC): $(PREFLATE_STAGED)/.stamp

$(GUEST): $(SRC) $(PREFLATE_STAGED)/.stamp
	$(EMCC) $(SRC) \
		-O0 -std=c++17 -fno-exceptions \
		-I$(PREFLATE_STAGED) \
		--no-entry \
		-sSTANDALONE_WASM=1 \
		-sALLOW_MEMORY_GROWTH=1 \
		-sINITIAL_MEMORY=67108864 \
		-sMAXIMUM_MEMORY=2147483648 \
		-sSTACK_SIZE=2097152 \
		-sEXPORTED_FUNCTIONS=_xt2png_preflate,_malloc,_free \
		-Wno-version-check \
		-o $(GUEST)

clean:
	rm -f $(GUEST)
