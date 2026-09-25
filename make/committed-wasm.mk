# Default goal: use the checked-in guest. Set WASM_REBUILD=1 to run emcc.
.PHONY: guest
.DEFAULT_GOAL := guest
guest:
	@if [ -n "$(WASM_REBUILD)" ] || [ ! -f "$(GUEST)" ]; then $(MAKE) $(GUEST); \
	else echo "$(notdir $(CURDIR)): using committed $(GUEST)"; fi
