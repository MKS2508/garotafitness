# garotafitness Specification

This document constrains the FitGirl volume extractor: atoms, composition, CLI, and the RimWorld corpus.

Status: approved
Genre: library + cli

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this
document are to be interpreted as described in BCP 14 (RFC 2119,
RFC 8174) when, and only when, they appear in all capitals.

## Intention

Job: Extract a local FitGirl repack into a destination tree without running `setup.exe`.

RimWorld is the test corpus. Reconstruction MUST derive file relationships,
destinations, compression parameters, and cleanup rules from installer metadata,
volume pipelines, and checksum manifests. Game titles, DLC names, fixed file
counts, and corpus-specific path lists MUST NOT select production behavior.

Non-goals:

1. Download, torrent, or scrape releases.
2. Create or recompress a repack.
3. Crack, emulate, or strip DRM.
4. Execute PE or DLL bytes from the installer.
5. Start a subprocess.
6. Support another scene group's installer layout.
7. Pack, list, or ship a GUI.
8. Apply installer side effects (registry, hosts file, wallpaper, music).

Inherited C (cite the file): `mise.toml`. Go comes from the mise registry. Compilers, make, and emscripten come from the mise `conda:` backend. Host `g++`, nix shells, and registry clang are not the toolchain.

## Technique

| ID | Input | Rule | Output |
|----|-------|------|--------|
| TEC-01 | argv | One command `extract` plus two directory operands | A run of the Extractor |
| TEC-02 | Source `fs.FS` plus Dest | The Extractor reads only Source. The Extractor writes only Dest. The CLI creates Dest if missing | Files under Dest |
| TEC-03 | The Extractor result | `log/slog` on stderr. Exit 0 only when every required Volume finished. Exit 1 on any failure | Process status |
| TEC-04 | `setup.exe` bytes plus Volume headers | Read them as data. Collect Encoder names and statically recover reconstruction records. Never map those bytes as executable or run installer scripts | Encoder names and reconstruction metadata |
| TEC-05 | One Encoder name | If an official implementation of that Encoder exists, wrap it as a Go stream primitive. If none exists, reverse-engineer that Encoder. One Encoder per package | `NewReader(io.Reader) (io.ReadCloser, error)` in the shape of `compress/gzip` |
| TEC-06 | A Volume (`ArC\x01`) | Parse the container in the shape of `archive/tar`. Send each solid block through the Encoder pipeline TEC-05 named | Members written through Dest |
| TEC-07 | Official C or C++ for an Encoder | Compile to `wasm32-wasip1`. Run the Guest in-process through wazero. WASI preview1 mounts Source read-only and Dest read-write. One Guest per Encoder when the official code is not Go | Decompressed bytes inside the same process |
| TEC-08 | Member path plus Dest root | Reject the member when the cleaned path leaves Dest | A contained write. An escape produces no write |

## Tooling

| TEC | Tool | Relation | We do not | Cite |
|-----|------|----------|-----------|------|
| TEC-01 | lewkit `x/cmd` | adopt | write cobra or hand-rolled flag parsing | github.com/lewtec/lewkit/x/cmd |
| TEC-02 | `io/fs.FS` for Source. Dest write port (Create, MkdirAll) | implement Dest | treat Dest as `fs.FS` | stdlib:io/fs (read-only; Dest write is a cited miss) |
| TEC-03 | `log/slog` | adopt | a second logger | stdlib:log/slog |
| TEC-04 | Volume method strings. `setup.exe` token scan | implement | run Inno Pascal, ISDone, or CLS | none (no Go Inno 5.5 library; `innoextract-go` is 6.x only) |
| TEC-05 LZMA | `ulikunitz/xz/lzma` | wrap | write LZMA | github.com/ulikunitz/xz/lzma |
| TEC-05 SREP | FreeArc / Intensity SREP compiled as a Guest | wrap | spawn `srep` | Intensity/srep ; mirror/freearc Compression/SREP |
| TEC-05 storing | identity `io.Reader` | implement | a Guest for uncompressed | stdlib:io |
| TEC-06 | `xredor/unarc` compiled as a Guest | wrap | write an ArC parser | github.com/xredor/unarc |
| TEC-07 | wazero plus conda emscripten | adopt | cgo, wasmtime, a subprocess | github.com/tetratelabs/wazero ; conda-forge:emscripten |
| TEC-08 | lewkit `x/path` Root (`os.OpenRoot`) | adopt | join host paths and check `..` by hand | github.com/lewtec/lewkit/x/path |
| TEC-03 MD5 | `crypto/md5` when `MD5/fitgirl-bins.md5` exists | adopt | skip a present checksum file | stdlib:crypto/md5 |

| Cell | Pick | C or D | Implements | Cite if C |
|------|------|--------|------------|-----------|
| Language | Go host. C++ Guests as `wasm32-wasip1` | D | TEC-05, TEC-07 | |
| Runtime | wazero | D | TEC-07 | |
| Persistence | none | D | CLI does not store | |
| UI | none | D | slog is the output | |
| Packaging | mise. `conda:` for make, g++, emscripten | C | TEC-07 | mise.toml |
| Identity | none | D | no accounts | |
| Host OS | Linux | D | first-class host | |

## Terminology

| Concept | Approved | Banned |
|---------|----------|--------|
| The program | garotafitness | the tool, the unpacker, the binary |
| Source tree | Source | input fs, in-dir, root |
| Write tree | Dest | output fs, out-dir, target |
| One `fg-*.bin` | Volume | bin, archive, arc, part |
| One file inside a Volume | Member | entry, item, archived file |
| One decompressor | Algo | Encoder, codec, compressor, method, filter |
| One pipeline step | Atom | stage, filter step |
| Decompress chain | Pipeline | method string |
| WASM module | Guest | wasm, plugin, runtime module |
| Composition root | Extractor | service, engine, manager |
| Installer file | `setup.exe` | Inno, wizard |
| Optional Volume | optional Volume | selective, bonus bin |
| Operator log | slog | logger, logrus, zap |

## Types

### Library

| Type | Exported | Identity or value | Mutable | Nil/error | Callers MUST NOT |
|------|----------|-------------------|---------|-----------|------------------|
| Extractor | yes | value. Holds Source and Dest | Dest changes during Extract | Nil Source or Dest: Extract returns error | Call Extract with Dest equal to a path outside the injected Dest |
| Source | yes (`fs.FS`) | value | no | Nil: Extract returns error | Write through Source |
| Dest | yes | value. Write port: MkdirAll, Create | yes | Nil: Extract returns error | Treat Dest as `fs.FS` |
| Volume | yes | identity = Source path of one `fg-*.bin` | no | Not `ArC\x01`: open returns error | Exec the file |
| Member | yes | value. Path, Pipeline, size | no | Escape of Dest: skip write, fail Extract | Use the raw path |
| Algo | yes | enum. Zero is invalid | no | Parse unknown name: AlgoInvalid | Treat Invalid as implemented |
| Atom | yes | value. Algo plus params | no | Unknown Algo: Extract returns error | Load a PE or DLL for that Algo |
| Pipeline | yes | value. Ordered Atoms, last first | no | Empty on a file Member: Extract returns error | Reorder atoms |
| BlockKind | yes | enum. Zero is invalid | no | Unknown kind: parse returns error | |
| Guest | no | identity = one wasm module | runtime instance | Instantiation fail: Extract returns error | Start a process for the Guest |

### CLI

| Command | Type it mutates | Transition | Bad input |
|---------|-----------------|------------|-----------|
| `extract SOURCE DEST` | Dest | Create Dest if missing. Write Members under Dest. Overwrite a Member that already exists | See Errors |

## Invariants

| ID | Predicate | On | Forbidden bypass |
|----|-----------|----|------------------|
| INV-01 | Extract writes only through Dest | Extractor | `os.Create` beside Dest |
| INV-02 | A Member path after clean stays under Dest | Member | write the raw name |
| INV-03 | No PE or DLL from Source runs | Extractor | LoadLibrary, mmap-exec, Wine |
| INV-04 | No child process starts | Extractor | `os/exec`, Guest `proc_exec` |
| INV-05 | Exit 0 means every required Volume finished | `extract` | exit 0 after a partial Dest |
| INV-06 | One Algo maps to one package | Algo | a second implementation of the same Algo |
| INV-07 | `setup.exe` is data | TEC-04 | call a function inside that image |
| INV-08 | A missing optional Volume is not a failure | Volume | require `fg-optional-*` |

## Errors

| Public operation | Bad input | One reaction |
|------------------|-----------|--------------|
| `extract` with a wrong operand count | bad argv | slog the reason. exit 1 |
| `extract` when an operand is not a directory | bad argv | slog the reason. exit 1 |
| `extract` when Source has no `fg-*.bin` | empty Source | slog. exit 1 |
| `extract` when `MD5/fitgirl-bins.md5` exists and a required Volume mismatches | corrupt Volume | slog the name. exit 1 |
| Extractor.Extract | nil Source | return error. CLI slog and exit 1 |
| Extractor.Extract | nil Dest | return error. CLI slog and exit 1 |
| Extractor.Extract | cancelled context | return error. CLI slog and exit 1 |
| Volume open | magic is not `ArC\x01` | return error. CLI slog and exit 1 |
| Encoder lookup | Atom.Algo is Invalid or has no Guest | slog the Atom. return error. exit 1 |
| Member write | path leaves Dest | slog the path. no write outside Dest. return error. exit 1 |
| Guest run | WASM trap, WASI fail, I/O fail | slog. return error. exit 1 |

Dest after exit 1 MAY be incomplete. Exit 0 MUST NOT describe an incomplete Dest.

## Actors

N/A for the library surface (genre=library).

| Actor | Obligations |
|-------|-------------|
| Operator | Supplies a local Source and a Dest path. Does not run `setup.exe`. Reads slog and the exit status |

## Capabilities

| ID | Actor | Sea-level goal |
|----|-------|----------------|
| CAP-01 | Operator | Extract the RimWorld corpus into Dest without running `setup.exe` |

## Public contract

Library: `Extractor.Extract` is the composition entry. Stream Algo packages live
under `stream/` and expose `NewReader`; `Decode` in the root package composes
them. Reconstruction transforms live under `reconstruct/` and take source bytes,
patch bytes, and compression parameters recovered from the installer records.
Volume open is the container entry. `4x4` Params hold the inner method.

CLI:

```
garotafitness extract SOURCE DEST
```

stderr is slog. stdout is unused. Exit 0 is success. Exit 1 is failure.

## Quality

| Concern | Measure, or why it cannot happen |
|---------|----------------------------------|
| Compatibility (library) | `NewReader` matches `compress/gzip`. Volume iteration matches `archive/tar` Next/FileInfo. A new Encoder is a new package |
| Error model (library) | Every exported call returns `error`. No panic on bad input. CLI maps any error to exit 1 |
| Exit contract (cli) | 0 complete. 1 any failure. No other codes |
| Untrusted input (cli) | Source is untrusted. INV-02 and INV-03 hold. Guest memory is the wazero limit (wasm32 4 GiB) |

## Security

In scope: untrusted Volume paths, untrusted `setup.exe` bytes, Guest sandbox.

Why code execution from the installer cannot happen: INV-03 and INV-07. Guests are modules this repo builds. Source PE files are not Guests.

Residual risk: a bug in a Guest can corrupt Dest or exhaust memory inside the 4 GiB cap. Dest after exit 1 may contain partial files.

## Success

- [ ] `garotafitness extract` on `/media/downloads/TORRENTS/RimWorld [FitGirl Repack]` writes the game tree under Dest and exits 0.
- [ ] The same command with the optional soundtrack Volume absent still exits 0.
- [ ] A Member name that contains `..` does not create a file outside Dest. The command exits 1.
- [ ] No process other than `garotafitness` runs during extract.
- [ ] `setup.exe` is never executed.
- [ ] Independent fixtures with different filenames, destinations, file counts,
  and compression parameters work without a game-specific configuration.
- [ ] `garotafitness extract` on `/media/downloads/TORRENTS/Songs of Conquest [FitGirl Repack]` writes the game tree under Dest and exits 0.
- [ ] `garotafitness extract` on `/media/downloads/TORRENTS/Farming Simulator 25 [FitGirl Repack]` writes the game tree under Dest and exits 0.

## Later work

1. An Encoder the RimWorld corpus does not use (XTool, lolz).
   Songs of Conquest also uses rzs (RAZOR stdio); that Encoder is in scope.
   pref (Precomp restore) is wrapped from official C++.
   Farming Simulator 25 also uses xt2png (XTool png+preflate) and tor (Tornado).
2. A `list` command.
3. A structured Inno 5.5 parse.
4. wasm64.
5. A Dest larger than the wasm32 memory cap.
6. Another scene group's layout.
7. Packing.

## Assumptions

| ID | Fact | If false |
|----|------|----------|
| AS-01 | RimWorld Volumes use FreeArc plus storing, SREP, and LZMA only | Add one Encoder package for the missing name. That work is in scope |
| AS-02 | wasm32 4 GiB is enough for this corpus | Later work items 4 and 5 move into scope |
| AS-03 | Member paths inside the Volumes are the Dest-relative game tree | TEC-04 stays data-only. Fix mapping inside Extractor |

## Decision history

- ADR-0001: argv is `extract SOURCE DEST`. Rejected tar-shaped flags.
- ADR-0002: C++ runs as in-process WASM through wazero. Rejected subprocess and cgo.
- ADR-0003: `setup.exe` is signal data. Rejected execution of installer DLLs.
- ADR-0004: Compilers come from mise `conda:`. Rejected nix, host g++, registry clang.
- ADR-0005: One Algo package at module root. Superseded by ADR-0007.
- ADR-0006: SREP v3 Future-LZ stays C++; Go owns the block loop. Guest is emscripten wasm. Go port later.
- ADR-0007: Stream atoms under `stream/`, reconstruction under `reconstruct/`. `Algo` is stream-only. Root still owns `Decode`.
