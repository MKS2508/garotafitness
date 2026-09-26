# ADR-0002: in-process WASM

Status: accepted

Official C++ Encoders compile to `wasm32-wasip1` and run inside wazero in the same process.
Go schedules every thread. The Guest links no pthreads and starts no thread.

Rejected a subprocess `unarc` or `srep`. Rejected cgo and wasmtime. Rejected a from-scratch Go FreeArc parser while `xredor/unarc` exists.
