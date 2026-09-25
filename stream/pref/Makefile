# Official Precomp restore guest. -O0 at link: conda binaryen 117 rejects
# emcc 4.0.9 wasm-opt flags (same as srep/mpz).
EMCC ?= emcc
PRECOMP = ../../third_party/precomp
GUEST = prefdec.wasm

GIF_SRC = $(addprefix $(PRECOMP)/contrib/giflib/,gifalloc.c gif_err.c dgif_lib_gcc.c egif_lib_gcc.c)
BZIP_SRC = $(addprefix $(PRECOMP)/contrib/bzip2/,bzlib.c blocksort.c crctable.c compress.c decompress.c huffman.c randtable.c)
ZLIB_SRC = $(addprefix $(PRECOMP)/contrib/zlib/,adler32.c crc32.c zutil.c trees.c inftrees.c inffast.c inflate.c deflate.c)
PACKARI_SRC = $(addprefix $(PRECOMP)/contrib/packjpg/,aricoder.cpp bitops.cpp)
PACKJPG_SRC = $(PRECOMP)/contrib/packjpg/packjpg.cpp
PACKMP3_SRC = $(addprefix $(PRECOMP)/contrib/packmp3/,huffmp3.cpp packmp3.cpp)
LZMA_COMMON = tuklib_physmem.c tuklib_cpucores.c common.c block_util.c easy_preset.c \
	filter_common.c hardware_physmem.c index.c stream_flags_common.c vli_size.c \
	alone_encoder.c block_buffer_encoder.c block_encoder.c block_header_encoder.c \
	easy_buffer_encoder.c easy_encoder.c easy_encoder_memusage.c filter_buffer_encoder.c \
	filter_encoder.c filter_flags_encoder.c index_encoder.c stream_buffer_encoder.c \
	stream_encoder.c stream_flags_encoder.c vli_encoder.c hardware_cputhreads.c \
	alone_decoder.c auto_decoder.c block_buffer_decoder.c block_decoder.c \
	block_header_decoder.c easy_decoder_memusage.c filter_buffer_decoder.c \
	filter_decoder.c filter_flags_decoder.c index_decoder.c index_hash.c \
	stream_decoder.c stream_buffer_decoder.c stream_flags_decoder.c vli_decoder.c
LZMA_SRC = $(addprefix $(PRECOMP)/contrib/liblzma/common/,$(LZMA_COMMON)) \
	$(addprefix $(PRECOMP)/contrib/liblzma/check/,check.c crc32_table.c crc32_fast.c crc64_table.c crc64_fast.c sha256.c) \
	$(addprefix $(PRECOMP)/contrib/liblzma/lz/,lz_encoder.c lz_encoder_mf.c lz_decoder.c) \
	$(addprefix $(PRECOMP)/contrib/liblzma/lzma/,lzma_encoder.c lzma_encoder_presets.c lzma_encoder_optimum_fast.c lzma_encoder_optimum_normal.c fastpos_table.c lzma_decoder.c lzma2_encoder.c lzma2_decoder.c) \
	$(PRECOMP)/contrib/liblzma/rangecoder/price_table.c \
	$(addprefix $(PRECOMP)/contrib/liblzma/delta/,delta_common.c delta_encoder.c delta_decoder.c) \
	$(addprefix $(PRECOMP)/contrib/liblzma/simple/,simple_coder.c simple_encoder.c simple_decoder.c x86.c powerpc.c ia64.c arm.c armthumb.c sparc.c)
BRUNSLI_SRC = $(addprefix $(PRECOMP)/contrib/brunsli/c/common/,ans_params.cc constants.cc context.cc huffman_tree.cc lehmer_code.cc platform.cc predict.cc quant_matrix.cc) \
	$(addprefix $(PRECOMP)/contrib/brunsli/c/dec/,ans_decode.cc bit_reader.cc brunsli_decode.cc context_map_decode.cc histogram_decode.cc huffman_decode.cc huffman_table.cc jpeg_data_writer.cc) \
	$(addprefix $(PRECOMP)/contrib/brunsli/c/enc/,ans_encode.cc brunsli_encode.cc context_map_encode.cc histogram_encode.cc jpeg_data_reader.cc jpeg_huffman_decode.cc write_bits.cc)
BROTLI_SRC = $(addprefix $(PRECOMP)/contrib/brotli/c/common/,dictionary.c transform.c) \
	$(addprefix $(PRECOMP)/contrib/brotli/c/dec/,bit_reader.c decode.c huffman.c state.c) \
	$(addprefix $(PRECOMP)/contrib/brotli/c/enc/,backward_references.c backward_references_hq.c bit_cost.c block_splitter.c brotli_bit_stream.c cluster.c compress_fragment.c compress_fragment_two_pass.c dictionary_hash.c encode.c encoder_dict.c entropy_encode.c histogram.c literal_cost.c memory.c metablock.c static_dict.c utf8_util.c)
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
INCLUDES = -I$(PRECOMP) -Iguest \
	-I$(PRECOMP)/contrib/liblzma -I$(PRECOMP)/contrib/liblzma/api \
	-I$(PRECOMP)/contrib/liblzma/check -I$(PRECOMP)/contrib/liblzma/common \
	-I$(PRECOMP)/contrib/liblzma/delta -I$(PRECOMP)/contrib/liblzma/lz \
	-I$(PRECOMP)/contrib/liblzma/lzma -I$(PRECOMP)/contrib/liblzma/rangecoder \
	-I$(PRECOMP)/contrib/liblzma/simple \
	-I$(PRECOMP)/contrib/brunsli/c/common -I$(PRECOMP)/contrib/brunsli/c/dec \
	-I$(PRECOMP)/contrib/brunsli/c/enc -I$(PRECOMP)/contrib/brunsli/c/include \
	-I$(PRECOMP)/contrib/brotli/c/include -I$(PREFLATE_STAGED)
DEFS = -DPRECOMPDLL -DBUILD_LIB -DHAVE_BOOL -D__unix
SRCS = $(GIF_SRC) $(BZIP_SRC) $(ZLIB_SRC) $(PACKARI_SRC) $(PACKJPG_SRC) $(PACKMP3_SRC) \
	$(LZMA_SRC) $(BRUNSLI_SRC) $(BROTLI_SRC) $(PREFLATE_SRC) \
	$(PRECOMP)/precomp.cpp guest/main.cpp guest/memfs.c guest/task_pool.cpp guest/otf_stub.cpp

include ../../make/committed-wasm.mk

$(PREFLATE_STAGED)/.stamp: guest/support/task_pool.h
	mkdir -p $(PREFLATE_STAGED)/support
	cp $(PRECOMP)/contrib/preflate/*.cpp $(PRECOMP)/contrib/preflate/*.h $(PREFLATE_STAGED)/
	cp $(PRECOMP)/contrib/preflate/support/* $(PREFLATE_STAGED)/support/
	cp guest/support/task_pool.h $(PREFLATE_STAGED)/support/task_pool.h
	touch $@

$(PREFLATE_SRC): $(PREFLATE_STAGED)/.stamp

$(GUEST): $(SRCS) guest/dlldecl.h guest/support/task_pool.h guest/otf_stub.cpp $(PREFLATE_STAGED)/.stamp
	$(EMCC) $(SRCS) \
		-O0 -fno-exceptions \
		$(INCLUDES) $(DEFS) \
		-include guest/dlldecl.h \
		--no-entry \
		-sSTANDALONE_WASM=1 \
		-sALLOW_MEMORY_GROWTH=1 \
		-sINITIAL_MEMORY=67108864 \
		-sMAXIMUM_MEMORY=2147483648 \
		-sSTACK_SIZE=2097152 \
		-sEXPORTED_FUNCTIONS=_pref_restore,_pref_out_ptr,_pref_out_len,_malloc,_free \
		-Wno-version-check -Wno-deprecated-declarations \
		-o $(GUEST)

clean:
	rm -rf $(GUEST) build
