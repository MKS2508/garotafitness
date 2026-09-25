# garotafitness

Extract a local FitGirl repack into its installed game tree:

```sh
go build -o bin/garotafitness ./cmd/garotafitness
bin/garotafitness extract '/path/to/repack' /path/to/output
```

`-v` raises slog detail (volumes, reconstruction records, recipe commands;
`-vv` includes each written member). `--help` and `--version` come from
lewkit `x/cmd`.

Keep `setup.exe`, the required `fg-*.bin` volumes, and `MD5/fitgirl-bins.md5`
together in the source directory. Optional volumes requested by setup records
are extracted when present. `setup.exe` supplies metadata and the installed-file checksum
manifest; it is read as data. Extraction runs entirely inside the Go process.

Reconstruction follows the extraction records recovered from `setup.exe` and
the recipes stored in its volumes. Those records supply archive filters,
working directories, compression parameters, patch inputs, output moves, and
cleanup paths. Setup component flags determine which volumes may be absent.
The extractor checks archive CRCs, patch checksums, and the
installed-file manifest before writing the final tree. Temporary files stay in
memory. Manifest entries resolve relative to the manifest destination recorded
in setup metadata. MPZ soundtrack decoding can take several minutes.

Supported recipe operations include FSB remuxing, LZMA packing, x2, RTPatch,
HDiffPatch, VCDIFF, 7z packing, Giants .dlc/.gar packing, file moves, copies,
and deletions. The extractor parses these
operations and calls its own implementations; it never runs the batch files or
their executables. Unknown operations and unresolved reconstruction arguments
return errors.

Compiled WASM modules are included. To rebuild the reconstruction modules, use
the compilers in `mise.toml` and run `mise run build:reconstruction`. The MPZ
translation is documented in [stream/mpz/guest/README.md](stream/mpz/guest/README.md), and the
RTPatch format in [reconstruct/x3/README.md](reconstruct/x3/README.md).

RimWorld is the integration-test corpus. Songs of Conquest is a second
repack used to catch encoders RimWorld does not exercise. Independent
fixtures also exercise different filenames, archive destinations, file
counts, compression options, manifest locations, and optional-volume names.
Run regression tests with `go test -p 1 ./...`. Corpus tests skip unless
`GAROTAFITNESS_CORPUS` points at the RimWorld repack directory. The Songs
of Conquest tests use `GAROTAFITNESS_CORPUS_SOC`. Farming Simulator 25
tests use `GAROTAFITNESS_CORPUS_FS25`. The full extraction tests also need
`GAROTAFITNESS_FULL_EXTRACT`:

```sh
GAROTAFITNESS_CORPUS='/path/to/RimWorld [FitGirl Repack]' go test -p 1 ./...
GAROTAFITNESS_CORPUS='/path/to/RimWorld [FitGirl Repack]' GAROTAFITNESS_FULL_EXTRACT=all go test . -run '^TestExtractInstalledRimWorld$' -timeout=1h
GAROTAFITNESS_CORPUS='/path/to/RimWorld [FitGirl Repack]' GAROTAFITNESS_FULL_EXTRACT=required go test . -run '^TestExtractInstalledRimWorld$' -timeout=1h
GAROTAFITNESS_CORPUS_SOC='/path/to/Songs of Conquest [FitGirl Repack]' go test -p 1 ./...
GAROTAFITNESS_CORPUS_FS25='/path/to/Farming Simulator 25 [FitGirl Repack]' go test -p 1 ./...
```
