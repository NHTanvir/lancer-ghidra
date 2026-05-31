# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-ghidra` — A Rust clone of Ghidra, the NSA reverse-engineering framework, built as part of the Lancer ecosystem — a complete 2026 AI-era bug bounty toolkit. It provides binary analysis, disassembly, debug-info parsing, and an embedded web interface, with an integrated LLM layer for AI-assisted reverse engineering. Currently in active scaffold/development phase per local `plan.md`.

## Architecture

- `src/main.rs` — Binary entry point; CLI argument parsing via `clap`
- `src/loader.rs` — Binary loading using `goblin` + `memmap2` (ELF, PE, Mach-O)
- `src/loaders_extra.rs` — Additional loader support for edge-case formats
- `src/disasm.rs` — Disassembly engine wrapping `iced-x86`, `yaxpeax-arch`, `yaxpeax-arm`
- `src/analysis.rs` — Core binary analysis pipeline
- `src/functions.rs` — Function detection and boundary analysis
- `src/cfg.rs` — Control-flow graph construction via `petgraph`
- `src/ir.rs` — Intermediate representation layer
- `src/debuginfo.rs` — DWARF/PDB debug-info parsing via `gimli` + `pdb`
- `src/demangle.rs` — Symbol demangling (C++, MSVC, Rust) via `cpp_demangle`, `msvc-demangler`, `rustc-demangle`
- `src/db.rs` — Persistent project database via `redb`
- `src/strings.rs` — String extraction from binary sections
- `src/hexdump.rs` — Hex dump rendering
- `src/xref.rs` — Cross-reference (xref) tracking
- `src/ai.rs` — LLM integration for AI-assisted analysis
- `src/llm.rs` — HTTP client wrapper around LLM API using `ureq`
- `src/web.rs` — Embedded HTTP server via `tiny_http`; serves `web_index.html`
- `src/script.rs` — Scripting engine via `rhai`
- `examples/` — Example scripts and usage

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- GUI is gated behind the default `gui` feature; `--no-default-features` builds a headless CLI binary.
- Library code lives in `src/lib.rs`; binary entry point in `src/main.rs`.
- Structured logging uses the `tracing` + `tracing-subscriber` stack; use `tracing::{info, warn, error, debug}` macros, never `println!` for diagnostics.
- Serialization uses `serde` + `serde_json`; all persistent structs must derive `Serialize`/`Deserialize`.
- The embedded web server (`src/web.rs`) serves a single-page interface from `web_index.html`; keep all HTML/JS in that file.
- WASM binary support is handled via `wasmparser`; treat it as a first-class target alongside ELF/PE/Mach-O.

## Build / test / run

```
build.bat                   # Windows → build\lancer-ghidra.exe
build-windows.bat           # Windows packaged dist → dist\lancer-ghidra-windows-x86_64\bin\lancer-ghidra.exe
./build-linux.sh            # Linux/macOS → build/lancer-ghidra
cargo build --release       # standard release build
cargo test                  # unit + integration tests
```

Requirements:
- Rust / Cargo (https://rustup.rs)
- (Windows) Visual C++ Build Tools 2019/2022

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
