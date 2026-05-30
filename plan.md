# RESEARCH DOSSIER: Ghidra

> Part of the Lancer ecosystem. A Rust clone of NSA's Ghidra — software reverse engineering suite. Build with Claude Code.
> Upstream: github.com/NationalSecurityAgency/ghidra (Java + C++, Ghidra 11.x → 12 in 2026). 2M+ LOC; cloning fully is multi-year.

## Feature Parity Mandate

**`lancer-ghidra` MUST ship with 100% feature parity to the upstream `ghidra` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `ghidra --help` (and the long-form man page / docs) must work in `lancer-ghidra --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-ghidra` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-ghidra --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

Ghidra is a software reverse engineering suite developed by the NSA's Research Directorate, open-sourced in 2019. It ingests binary executables (ELF/PE/Mach-O/raw/firmware) across 30+ processor architectures, disassembles them, lifts them to a uniform intermediate representation (P-code), runs a battery of analyzers (function boundary detection, type propagation, parameter recovery, constant propagation), decompiles each function to readable C-like pseudocode, lets you annotate everything (rename, retype, comment), and supports multi-user collaboration via a shared project server.

Concretely:
- **Disassembler**: shows machine code → assembly listing per function, with cross-references
- **Decompiler**: produces C-like pseudocode for any function — the headline feature
- **Data type system**: full C-style types (struct, union, enum, typedef, function pointers), can import header files, propagates types through decompilation
- **Symbol manager**: every label/function/variable can be renamed; renames propagate everywhere
- **Cross-reference graph**: every function-to-function and data-reference is indexed
- **Scripting**: Java (native), Python via Jython 2.7, Python 3 via Ghidrathon
- **Headless mode**: `analyzeHeadless` CLI runs a full project analysis + script pipeline without GUI
- **Project server**: multiple analysts work on the same binary
- **Plugin/extension architecture**: extensions ship as zip "extensions"
- **Diffing**: compare two versions of a binary
- **Emulator**: P-code-level emulator

## Cloning reality check

**The honest truth**: Ghidra is over 2 million lines of Java + C++. The decompiler alone is ~150k LOC of C++. The Sleigh processor specification system is a domain-specific compiler. Multi-arch support means hundreds of `.slaspec` files. The GUI is hand-tuned Java Swing. **A solo dev in 6-12 months cloning all of Ghidra is not happening.**

What IS realistic:

| Component | Solo-dev 6-12 month feasibility | Verdict |
|---|---|---|
| ELF/PE/Mach-O parser | YES | `goblin` |
| x86_64 disassembler | YES | `iced-x86` |
| ARM64 disassembler | YES | `bad64`/`disarm64` |
| Function boundary detection | YES | Linear sweep + recursive descent |
| Cross-reference DB | YES | Just a graph |
| Pseudo-IR (your own simple form) | YES | A few weeks |
| Decompiler (C-like pseudocode) | NO (year-long+ project) | Skip v1 or wrap |
| Multi-architecture via Sleigh-style spec | NO | Pick one arch |
| GUI with Ghidra-comparable UX | NO (year+) | Web UI in Lancer is fine; show less |
| Headless CI mode | YES | If you ship a CLI |
| Multi-user / project server | NO (months alone) | Skip |
| P-code emulator | NO | Way too complex |
| Plugin API | YES | Trivial — `dyn Trait` + script loading |

**Realistic MVP (6-9 months)**:
- x86_64 ELF + PE
- `iced-x86` for disassembly
- Function detection (entry point + symbol table + linear sweep + heuristics)
- Cross-reference index
- Simple-IR lift (each insn → tuple of "operation + operands")
- Disassembly listing in web UI
- Function navigator / call graph
- Symbol rename
- Comments
- Strings extraction
- Hexdump viewer
- **No decompiler** — disassembler-only v1

**Phase 2 (months 9-18)**:
- ARM64 support
- Mach-O
- **Decompiler integration**: subprocess to `ghidra-headless` itself (LOL, embarrassingly) or vendor an existing open-source decompiler

**Decompiler reality**:
- Writing a decompiler is a research-grade undertaking. Ghidra's decompiler is the work of one engineer over many years.
- Rust ecosystem has near-zero in this space. `salvo` was an attempt, mostly dead.
- Real options: (a) shell out to Ghidra's decompiler binary (ironically), (b) shell out to RetDec, (c) use `binaryninja` API (commercial), (d) use `radare2`'s `r2dec` plugin (JS-based, but real), (e) LLM-based decompilation (real research direction — "LLM4Decompile", "DeGPT", "Nova" papers 2024-2025).

## Internal architecture

Ghidra is a Java project that bundles a C++ decompiler. Top-level:

```
ghidra/
├── Ghidra/
│   ├── Framework/             # Core platform
│   │   ├── Generic/  Project/  DB/  Docking/  Help/
│   ├── Features/
│   │   ├── Base/              # Code browser, symbol manager, references
│   │   ├── Decompiler/        # JNI bridge to C++ decompiler
│   │   │   ├── ghidra/app/decompiler/    # Java side
│   │   │   └── src/decompile/cpp/        # The decompiler in C++ (!)
│   │   │       ├── action.cc / .hh       # Transform passes
│   │   │       ├── architecture.cc
│   │   │       ├── block.cc
│   │   │       ├── flow.cc               # Control flow recovery
│   │   │       ├── funcdata.cc           # Function-level data
│   │   │       ├── heritage.cc           # SSA construction
│   │   │       ├── jumptable.cc          # Switch recovery
│   │   │       ├── op.cc
│   │   │       ├── pcoderaw.cc / pcodeop.cc
│   │   │       ├── ruleaction.cc         # Simplification rules
│   │   │       ├── slghpatexpress.cc
│   │   │       ├── typeop.cc
│   │   │       ├── varnode.cc            # SSA variables
│   │   │       └── ... (~150 .cc files)
│   │   ├── FunctionGraph/  BytePatterns/  FileFormats/
│   │   ├── Python/            # Jython 2.7
│   │   ├── PyGhidra/          # Python 3 via Jpype
│   │   └── ProgramDiff/  ProgramGraph/  VersionTracking/
│   ├── Processors/            # Sleigh specs! One module per ISA
│   │   ├── x86/  ARM/  AARCH64/  PowerPC/  MIPS/  RISCV/  6502/  Z80/  Sparc/ ... (30+ ISAs)
│   │   └── data/languages/<arch>.slaspec  # The Sleigh specification source
│   └── Extensions/
└── support/                   # Launch scripts
```

### Sleigh

Sleigh is the secret weapon. DSL for processor specifications. A `.slaspec` file describes:
- Endianness, word size, alignment
- Memory spaces (RAM, register, constant)
- Token decomposition
- Constructor table (bit pattern → mnemonic + operands)
- **Each instruction's semantics expressed as P-code operations**

Example (simplified ARM):
```
:ldr Rd, [Rn, #imm] is opcode=0xE5 & Rd & Rn & imm {
  ptr = Rn + imm;
  Rd = *:4 ptr;
}
```

Sleigh compiles this DSL to a binary spec file (`.sla`) the disassembler and lifter read at runtime.

**Implication**: if you clone Sleigh's parser + the spec files, you get every Ghidra-supported arch for free. **In practice**, writing a Sleigh-compatible compiler is itself a major project; `sleigh-rs`, `pcode-rs` started but none production-ready as of 2026. Realistic plan: pick one arch, hand-code it.

### P-code

Bridge between machine code and decompilation. Register-transfer-language-ish IR with ~80 unique operations: COPY, LOAD, STORE, INT_ADD, INT_SUB, INT_MULT, INT_AND, INT_OR, INT_XOR, INT_LEFT, INT_RIGHT, INT_SLESS, INT_EQUAL, BRANCH, CBRANCH, BRANCHIND, CALL, CALLIND, RETURN, FLOAT_ADD, ..., NEW.

Each machine instruction lifts to 1-30 P-code ops. P-code operates on "varnodes" (SSA-style locations: register, memory address, temporary, constant).

Decompiler pipeline takes raw P-code → SSA form → simplification rules → control flow recovery → type inference → C-like emission. **P-code is portable** — write the decompiler against P-code once, run it for any arch with a Sleigh spec.

### Decompiler internals

C++ program (`decompile.exe`/`decompile`) that Ghidra spawns as a subprocess per function. Communication via stdin/stdout XML. Phases:

1. **Raw P-code generation** — Sleigh lifts each insn
2. **Heritage** — SSA construction (phi nodes for joins)
3. **Indirect call resolution**
4. **Jumptable recovery** — recognize switch table patterns
5. **Control flow restructuring** — basic-block graph → structured (if/while/for)
6. **Type propagation** — given function signature types, propagate through assignments
7. **Constant simplification** — apply ~hundreds of rule transformations
8. **Variable merging** — combine SSA versions back into "user-readable" variables
9. **Stack analysis** — recognize stack-allocated locals
10. **Output emission** — emit C-like text

Roughly 50-150ms per function on modern hardware.

### Database (Ghidra DB)

Ghidra ships its own embedded transactional KV store. Not SQLite — hand-rolled disk format with copy-on-write pages and undo/redo. Every action (rename, comment, type set) is a transaction.

### Scripting

- **GhidraScript** (Java): subclass `GhidraScript`, implement `run()`. Compiles at script load time via Eclipse Java compiler.
- **Python (Jython)**: same API; runs in Jython 2.7. Slow startup; Python 2 limitations.
- **Python 3 (Ghidrathon)**: Mandiant extension, uses Jep. Modern scripts almost always use this.

## Granular feature catalog

**Loaders**: ELF, PE/COFF, Mach-O, Java class, Android DEX, Intel Hex, Motorola S-record, Raw binary, WebAssembly (community), LLVM Bitcode (community), Various ROM formats.

**Analysis (default analyzers)**: ASCII Strings finder, Function start detection, Stack analysis, Constant propagation, Decompiler parameter ID, Reference creation, Demangler (Itanium ABI, MSVC, Rust), Function ID / Library function recognition, DWARF debug info parsing, PDB symbol parsing.

**Disassembler views**: Linear listing, Function graph (basic block graph), Bytes/instructions/operands columns customizable.

**Decompiler**: C-like pseudocode, highlight matching variables, rename variable from decompile (propagates), retype variable, edit function signature, multiple comment types (pre, post, EOL, plate, repeatable), Decompiler diff mode.

**Data type manager**: Built-in types, Import C header files, Apply structures to memory regions, Create function signatures, BSim (binary similarity DB).

**Symbol manager**: Function symbols, label symbols, parameter symbols, Namespaces, Equate.

**Memory map**: Define memory blocks (ELF segments / PE sections auto-loaded), Mark code vs data, Set permissions.

**Cross-references**: Every reference indexed, filter by type.

**Scripting**: Bundled scripts, custom scripts in Java/Python(2)/Python(3), GhidraScript API surface.

**Headless / CLI**: `analyzeHeadless`, pre/post scripts, custom loader specification.

**Project server**: Multi-user shared project, check-in/out workflow, version history.

**P-code emulator**: Run a function with controlled state, trace execution.

**Extension API**: Plugins (Java classes implementing `Plugin`), loaders, analyzers, processors, decompiler ruleactions.

**Versioning / Diff**: Program Diff, Version Tracking (great for patch-diffing CVE fixes).

**Recent additions (2024-2026)**: PyGhidra / Ghidrathon standardized, AI assist hooks in 11.x (decompiler annotation suggestions), MCP integration experimental, WebAssembly loader mainlined, eBPF processor spec contributed.

## Expanded feature catalog (2025-2026 deep research)

The base catalog above is incomplete. Below is the fully-enumerated upstream feature surface as of Ghidra 12.1 (May 2026), drawn from the official ChangeHistory / WhatsNew and release notes for 11.1, 11.2, 11.3, 11.4.x, 12.0.x, 12.1. **`lancer-ghidra` must support every item here.**

### Loaders (must all ship)
- **PE / PE32+ / COFF** — Windows executables, object files, with CV/PDB hints
- **ELF** — 32 + 64 bit, all standard machines + relocations
- **Mach-O** — single-arch + universal (FAT) + `dyld_shared_cache` + **Mach-O file sets (iOS/macOS kernelcache)** added 11.1
- **MZ / DOS** — legacy DOS executables
- **Java class** (`.class`) and **JAR**
- **Android DEX / ODEX**
- **Android OAT** (ART runtime)
- **APK** (filesystem loader extracting DEX/native libs/resources)
- **Intel Hex** / **Motorola S-record** / **TI-TXT**
- **Raw binary** with custom base + arch
- **WebAssembly** (`.wasm`) — mainlined community spec
- **LLVM Bitcode** (community)
- **Unix A.out** — added 11.4
- **SquashFS** filesystem — added 11.1
- **LZFSE decompression** support for iOS/macOS payloads — added 11.1
- **Various ROM formats** (NES/SNES/GB/etc. via community RetroGhidra)
- **Firmware container parsers** (UEFI capsule, U-Boot uImage, TRX, Linksys/Tenda router blobs — community)
- **GZF / Ghidra zip format** for project export/import
- **Link-files** (internal + external folder/file references in projects) — added 12.0

### Processors (Sleigh specs that must all work)
- **x86** (16/32) + **x86_64** — including AVX, AVX-512, **SSE4a** (added 11.4.3), AMX, TSX
- **ARM** (ARMv4–ARMv8) + **AArch64** (ARMv8/v9) — including ARM Cortex stack-limit register insns (added 11.4)
- **PowerPC 32/64**, **PowerPC VLE**
- **MIPS 16/32/64**, **microMIPS**
- **SPARC 32/64**
- **RISC-V** RV32/RV64 + standard extensions + custom-extension support refactor + **AndeStar v5** (added 12.0)
- **NDS32** — added 12.0
- **AVR8 / AVR32** — Atmel/Microchip
- **8051** / 6502 / 6800 / 6809 / 68xxx (Motorola 68k)
- **Z80 / Z180 / eZ80**
- **V850**
- **MSP430**
- **PIC 12/16/17/18/24**
- **CR16C**
- **HCS08 / HCS12**
- **TLCS-900 / TLCS-90**
- **PA-RISC**
- **eBPF** — including ISA v4 (added 11.1)
- **Intel MC16/60 + MC16/80** — added 11.2
- **Java bytecode** / **DEX bytecode** as processors
- **JVM** / **Dalvik** opcode semantics
- **Xtensa** (community)
- **Tricore** (community)
- **SuperH (SH-2/3/4)** (community)

### Sleigh language additions (track every release)
- Constructor-pattern improvements for variable-length insns (used by x86 prefixes, ARM Thumb, RISC-V compressed)
- `align` / pattern macros / `local` keyword
- `pcodeop` user-defined ops (used by debugger / co-processor abstractions)
- `:` instruction display section vs semantic section split
- `attach variables` / `attach names` / `attach values`
- Cross-context register support for ARM Thumb mode, MIPS micromips, RISC-V RVC
- New `delayslot()` lifter primitive for SPARC/MIPS
- Endianness override per memory space
- `signed` / `unsigned` token attribute keywords

### P-code IR opcodes (all must be implemented in the lifter + decompiler IR)
- COPY, LOAD, STORE
- INT_ADD, INT_SUB, INT_MULT, INT_DIV, INT_REM, INT_SDIV, INT_SREM
- INT_AND, INT_OR, INT_XOR, INT_NEGATE, INT_2COMP
- INT_LEFT, INT_RIGHT, INT_SRIGHT
- INT_EQUAL, INT_NOTEQUAL, INT_LESS, INT_LESSEQUAL, INT_SLESS, INT_SLESSEQUAL
- INT_CARRY, INT_SCARRY, INT_SBORROW
- INT_ZEXT, INT_SEXT
- BRANCH, CBRANCH, BRANCHIND, CALL, CALLIND, CALLOTHER, RETURN
- FLOAT_ADD, FLOAT_SUB, FLOAT_MULT, FLOAT_DIV, FLOAT_NEG, FLOAT_ABS, FLOAT_SQRT
- FLOAT_EQUAL, FLOAT_NOTEQUAL, FLOAT_LESS, FLOAT_LESSEQUAL
- FLOAT_INT2FLOAT, FLOAT_FLOAT2FLOAT, FLOAT_TRUNC, FLOAT_CEIL, FLOAT_FLOOR, FLOAT_ROUND, FLOAT_NAN
- BOOL_NEGATE, BOOL_AND, BOOL_OR, BOOL_XOR
- PIECE, SUBPIECE, POPCOUNT, LZCOUNT
- SEGMENTOP, CPOOLREF, NEW, INDIRECT, MULTIEQUAL, PTRADD, PTRSUB, CAST
- (P-code emulator opcode set) — JIT-accel P-code emulator added 11.3
- (Symbolic P-code via Z3) — concolic / hybrid emulator added 12.0

### Decompiler features (per upstream parity)
- C-like pseudocode emission with type-aware operator rendering
- Variable highlight + same-variable cross-line highlight
- Rename-from-decompile → propagates to global symbol DB
- Retype variable from decompile (inline struct/typedef editor)
- Edit function signature inline (return type + params + calling conv + varargs)
- Multiple comment kinds: pre, post, EOL, plate, repeatable
- Decompiler **diff mode** (compare two versions of a function or two binaries)
- **Stack strings** auto-recovery — added 11.2
- Switch analysis with duplicated guard blocks — improved 11.4.2
- Boolean expression analysis (no reversed-meaning bugs) — fix 11.4.2
- Middle-mouse highlight on if/else/while keywords — restored 11.4.3
- Token-based highlight model (every C token clickable)
- Per-function override of calling convention, name mangling, return storage
- Jumptable manual override
- Force decompile / clear decompiler cache per-function
- Decompiler XML/JSON output via headless
- Library function ID overlay in decompile view

### Debugger plugin (full subsystem — barely mentioned earlier)
The Ghidra Debugger is a first-class subsystem with its own UI, tracing model, and back-ends. `lancer-ghidra` must mirror it.

- **TraceRMI protocol** — replaced GADP in 11.1; primary RPC for back-end connectors
- **gdb / gdbserver** connector
- **lldb** connector + **macOS kernel debugging via lldb** (added 11.3)
- **dbgeng / WinDbg / x64dbg** connector — **x64dbg ↔ Ghidra bidirectional sync** added 12.0
- **Time-Travel Debugging (TTD)** via dbgeng — added 11.1
- **Wine-based Windows debugging on Linux** — added 11.1
- **Meta's drgn** debugger connector (Linux kernel) — added 11.4
- **JDI connector** for Java / Android JVM debugging — added 11.3
- **Trace database** — record + replay execution traces, scrub timeline
- **P-code emulator** as a debug target (run binary in-process with controlled state)
- **JIT-accelerated P-code emulator** — added 11.3
- **Z3 symbolic / concolic emulator** — experimental, added 12.0
- Watchpoints + conditional breakpoints + memory-region watches
- Register / stack / memory panes with type overlay
- Module / thread / region listing
- Live decompile of current PC's function
- Static-vs-dynamic correlation: map running code back to project listing

### BSim (binary similarity)
- **BSim installed by default** as of 11.4
- PostgreSQL ≥15.13 backend
- Elasticsearch backend improvements (11.3)
- Function-vector index + nearest-neighbor search
- Cross-binary clone detection / library function identification
- BSim CLI tools (`bsim_ctl`, `bsim`)
- Experimental BSim cloud (Ghidra 11.4-11.5)

### Function-ID + Function-ID-Lite
- Byte-pattern library function recognition
- Per-architecture FID DB shipping
- FID DB build pipeline (analyze well-known libs → dump signatures)
- Apply-FID analyzer in headless pipeline

### Headless analyzer (`analyzeHeadless`)
Every CLI flag must be supported in `lancer-ghidra --cli analyzeHeadless`:
- `-import` / `-process` / `-noanalysis` / `-readOnly`
- `-preScript` / `-postScript` with arg passthrough
- `-scriptPath` + per-script project state isolation
- `-loader` override (specify loader by name)
- `-processor` override (specify language spec)
- `-cspec` (compiler spec)
- `-recursive` for directory imports
- `-overwrite` / `-deleteProject`
- `-okToDelete`
- `-max-cpu`, `-analysisTimeoutPerFile`
- `-connect <user>` (Ghidra Server)
- `-p` (password from prompt / file)
- `-keystore <file>` (PKI auth)
- `-commit <comment>` for shared projects
- `-log` / `-stdout` / `-loglevel`
- Script output capture as JSON / XML / GZF

### GhidraServer (shared project server)
- Multi-user check-in / check-out workflow
- Version history per file with diff browsing
- PKI + LDAP + local-user auth
- Per-folder permissions
- Server admin CLI: `svrAdmin add/remove/passwd/migrate`
- Repository compaction
- TLS configuration

### Scripting environments
- **Java GhidraScript** (subclass + `run()`) — Eclipse compiler at load
- **Jython 2.7.4** (legacy; needs `# @runtime Jython` header in 12.0+) — upgraded 11.3
- **PyGhidra / Ghidrathon (CPython 3)** — integrated 11.3, default in **PyGhidra 3.0** for Ghidra 12.0
- **GhidraDev plugin** for Eclipse + **Visual Studio Code integration** (added 11.3)
- **GhidraDev 5.0.0** with PyGhidra project templates (11.4.3)
- Script bundles: `.gpr` archive with manifest + scripts + extensions
- Headless script chaining + return values

### Structure / type editor
- Hand-edit struct / union / enum / typedef / function-pointer
- Apply struct to memory + auto-pad
- Import C header file → resolve into Data Type Manager
- BitField support
- Function signature editor (return + params + calling conv + varargs)
- Equate / mask editor
- Archive types (built-in, program, project archives)
- Search by type name / size / regex

### Memory map editor
- Add / split / join memory blocks
- Bit-mapped overlay blocks
- Permissions (R/W/X) per block
- File-byte vs initialized vs uninitialized
- Memory block search-and-replace

### Cross-reference index
- Code-to-code, code-to-data, data-to-code, data-to-data refs
- Filter by ref-type (call, jump, read, write, computed)
- Reverse refs (who calls me / who reads this byte)
- Reference graph view

### Function graph
- Per-function CFG view
- Nested layout, compressed layout, **new function graph layouts** added 11.3
- Vertex grouping, collapsing, mini-map
- Sync with listing + decompile pane

### Program graph + Data graph
- Whole-program call graph
- **Data graph** (reference relationships between in-memory data items) — added 12.0
- Export to GraphML / DOT / JSON

### Program diff + Version Tracking
- Byte-level + listing-level + decompile-level diff
- Version Tracking tool for patch-diffing (CVE work)
- Correlator types: exact, exact-by-bytes, exact-by-instructions, reference, ...
- Markup propagation across versions

### Emulator (concrete + symbolic)
- Standard concrete P-code emulator
- JIT-accel emulator (11.3+)
- **Z3 symbolic emulator** for hybrid concolic execution (experimental, 12.0+)
- `PcodeEmulator` composition-based API (12.0 refactor)
- Stepping + breakpoints inside emulator
- Memory write tracking + register snapshots

### URL / link plumbing
- **GhidraGo URL** scheme (`ghidra://...`) for cross-tool linking — added 12.0
- Link-files (internal + external) as first-class project entries — added 12.0

### DWARF / PDB
- DWARF 2/3/4/5 parsing (gimli equivalent)
- PDB7 + PDB2 parsing
- Demangler: Itanium ABI, MSVC (with `MangledContext` refactor 11.3), Rust, Swift, D, Go
- DWARF function frame info / location lists / inlined subroutine ranges

### Golang support
- Recognize Go runtime structures, goroutines, channels, slice/map types
- Golang 1.15 → **1.23 with closures + generics** (11.3, 11.4)
- Pclntab parsing for function names

### Rust binary support
- Recognize Rust mangling + std library functions
- Rust trait object devirtualization helpers (community)
- Improved Rust analysis 11.1+

### Build & runtime requirements (must match)
- **JDK 21** minimum (11.2+)
- **Gradle 9** (11.4.3+)
- **Python 3.9–3.13** for PyGhidra and debugger plumbing

## Engineering hard parts

1. **The decompiler** — this is the project. Pattern-based simplification, type propagation, SSA-then-back, control-flow restructuring (Goto elimination, loop recovery from arbitrary CFG), expression rebuilding. Ghidra's took 10+ years.
2. **Sleigh compiler** — DSL parser + semantic checker + binary emitter. Few thousand LOC alone. Then you need a `.sla` interpreter at runtime.
3. **Function boundary detection** on stripped binaries — heuristic combination of: symbol table, prologue patterns, control flow from entry point, ATC. Get this wrong and the rest of the analysis is garbage.
4. **Calling convention recovery** on stripped binaries — required for decompilation. Done via constant propagation backward from call sites.
5. **Jump table recovery** — `jmp [base + idx*4]` patterns must be recognized to follow switch statements; ARM has different patterns; LLVM produces different patterns than GCC.
6. **Type recovery** — without DWARF/PDB, recovering struct layouts from access patterns is research-grade.
7. **C++ class hierarchy recovery** — vtables, RTTI, name mangling.
8. **Position-independent code + PIE relocations** — ASLR-friendly code patterns confuse simple analyzers.
9. **Exception handling tables** parsing is needed to find functions reliably.
10. **Multi-arch matters** — bug bounty + reverse engineering work is mostly x86_64 and ARM64, but firmware (MIPS, PowerPC, AVR, RISC-V) shows up in IoT bug bounty.
11. **GUI tooling** — Ghidra's listing+decompile dual-pane synchronized navigation is a UX masterclass.
12. **DB engine** — you don't need to clone Ghidra's hand-rolled DB; SQLite or sled/redb work. Operations must be transactional with undo/redo.
13. **Performance** — Ghidra is slow on big binaries (Chromium ELF takes hours). Rust can be much faster *if* you design data structures well from day one.

## Rust library mapping

| Need | Crate | Notes |
|---|---|---|
| ELF/PE/Mach-O parse | `goblin` | Standard, mature |
| DWARF debug info | `gimli` | Standard |
| PDB | `pdb` | Microsoft PDB parser by getsentry |
| x86/x64 disassembly | `iced-x86` | The gold standard |
| ARM64 disassembly | `bad64`, `disarm64`, `bddisasm` | bad64 wraps Bad64 C lib |
| ARM (32-bit) | `capstone` (FFI), `unicorn-engine` for emulation | No pure-Rust full disasm |
| RISC-V | `raki`, `riscv-isa-parser` | Niche |
| MIPS | shell out to `capstone` | Limited Rust |
| Capstone wrapper | `capstone-rs` | Fallback for any arch capstone supports |
| Cross-arch wrapper | `yaxpeax-*` family | Decent coverage |
| Sleigh-style IR | None production — `pcode` crate early stage | Roll your own or vendor |
| Decompiler | None mature in Rust — `decomp`, `salvo` early | Wrap external tool |
| Demangler | `cpp_demangle`, `msvc-demangler-rust`, `rustc-demangle` | All exist |
| Symbol table | hand-roll over goblin | Trivial |
| Binary diffing | `radare2-r2pipe` (control radare2) | Or implement basic CFG diff |
| Embedded DB | `sled`, `redb`, or SQLite (`sqlx` / `rusqlite`) | Pick `redb` for pure Rust + ACID |
| Graph (call graph, CFG) | `petgraph` | Standard |
| Async runtime | `tokio` | Standard |
| GUI (if not web) | `egui`, `iced`, `slint` | All viable; egui is fastest to build |
| Web frontend | Svelte (matches Lancer) | Use Lancer's stack |
| Strings extraction | `binary-strings` or hand-roll | Trivial |
| Embed a decompiler | shell to `ghidra-decompiler`, `retdec-rs`, `r2pipe` to r2dec, `binaryninja` (commercial), or LLM | All compromises |
| C parser (for type imports) | `lang-c` or `tree-sitter-c` | For struct definitions |
| Hexview rendering | `hexyl`'s formatter | Or hand-roll |
| YAML config | `serde_yaml` | Standard |

**For the decompiler problem specifically**: in 2026, the most promising path is **LLM-based decompilation** — feed disassembly to a code-trained model and ask for C. Quality is OK for small functions, awful for large; but it's the only path a solo dev can credibly take. Combine with iced-x86's listing + LLM rewrite + light type inference and you have a usable "AI decompiler" pane that ships in months, not years.

## 2024-2026 state

- **Ghidra 11.0** (early 2024): big BSim improvements, eBPF support, decompiler stability fixes
- **Ghidra 11.1-11.2** (mid 2024): Ghidrathon merged into core, MCP-style integration prototyped, improved Rust binary support
- **Ghidra 11.3** (late 2024-early 2025): GraalPy evaluated; better RISC-V; UI dark mode polished
- **Ghidra 11.4-11.5** (2025): assistant pane for LLM integration; experimental BSim cloud; better Apple silicon native build
- **Ghidra 12** (early 2026): rumored unified plugin marketplace, deeper AI-assist (suggest function names, suggest type annotations); fresh decompiler perf work
- **Ghidrathon** is now the canonical way to script Ghidra in Python 3
- **NSA continues active development**
- **Community ecosystem**: BinDiff (open-sourced by Google in 2023), Sigrok-style firmware loaders, the "Ghidra-FunctionID-Lite" for cheap library matching
- **AI-decompiler trend**: papers like "LLM4Decompile", "DeGPT", and "Nova" published 2024-2025 show 30-60% functional correctness on stripped binaries when LLMs paired with verifiers

### 2026-05-30 deep-research update

Refreshed against upstream `NationalSecurityAgency/ghidra` (master, Ghidra 12.1 released 2026-05-13; 53 total releases on the repo).

- **Ghidra 11.4** (June 2025) → **11.4.1** (Jul) → **11.4.2** (Aug) → **11.4.3** (Dec 2025): added x86 SSE4a, ARM Cortex stack-limit register, Unix A.out loader, BSim shipped by default, Golang 1.23 closures/generics, drgn debugger connector, decompiler switch-with-duplicated-guard handling, GhidraDev 5.0.0 with PyGhidra templates, Gradle 9.
- **Ghidra 12.0** (Dec 2025) + **12.0.1–12.0.4** (Jan–Mar 2026): NDS32 + RISCV AndeStar v5 processors, **PyGhidra 3.0 is now the default scripting engine** (Jython requires explicit `# @runtime Jython` header), experimental **Z3 symbolic / concolic emulator**, **link-files** (internal + external folder/file references), **x64dbg ↔ Ghidra synchronization**, `PcodeEmulator` composition-based refactor for upcoming JIT, **data graph** visualization, **GhidraGo `ghidra://` URL** scheme, JDK 21 mandatory, Python 3.9–3.13 for debugger + PyGhidra.
- **Ghidra 12.1** (May 13, 2026): latest stable; tracked as the current parity target.
- **Debugger subsystem** in 11.1–12.0 is now a first-class peer of the Code Browser: **TraceRMI** replaces GADP, **Time-Travel Debugging** via dbgeng, **Wine-based Windows debugging on Linux**, **JDI** for Java/Android, **lldb-based macOS kernel debug**, **drgn** for Linux-kernel introspection. `lancer-ghidra` must include a corresponding `lancer-ghidra-debugger` companion or panel.
- **Loaders** added since 2024: Unix A.out, SquashFS filesystem, Mach-O file sets (iOS/macOS kernelcache), LZFSE decompression, COFF AARCH64 relocations, link-file format. The plan now enumerates these.
- **Plan additions in this update**: full expanded loader list, full processor list (eBPF v4, NDS32, AndeStar v5, V850, MC16/60, MC16/80, TLCS-900, HCS08/12 etc.), full P-code opcode list, Sleigh language feature surface, Debugger plugin subsystem, Structure editor, Memory map editor, Reference index, Function graph + Data graph, Program diff + Version Tracking, Function-ID / FID-Lite, GhidraServer admin surface, headless analyzer flag matrix, PyGhidra 3.0 + Jython 2.7.4 + GhidraDev 5.0.0 scripting surface, Z3 / JIT / concrete emulator triad, GhidraGo URL plumbing, JDK 21 + Gradle 9 + Python 3.9–3.13 toolchain requirements.

## Bug bounty workflows

- **Reversing custom binary protocols** in mobile / IoT apps to find auth bypass / parser vulns
- **Finding native lib vulns** in Android apps (the `.so` files MobSF lists; Ghidra is where you actually look for the bug)
- **Patch-diffing CVE fixes** to identify the actual bug, then write a PoC for unpatched versions
- **Firmware reverse engineering** of routers, cameras, smart home (Tenda/TP-Link/D-Link forever flowing with bounties)
- **Hardware wallet / DRM analysis** (high-end, rare)
- **Recovering obfuscated string decryption routines** for malware analysis
- **Cross-referencing imports** — find every call to `system()`, `popen()`, `dlopen()` in a stripped binary
- **Recognizing crypto** — Ghidra often auto-recognizes AES S-boxes or MD5 constants
- **Patch generation** — find a function, write a binary patch, validate via emulator

## AI augmentation ideas

1. **Function naming**: take disassembly + cross-refs, ask LLM "what does this function do? suggest a name and short description". Apply rename. Repeat function by function in batch headless mode.
2. **Type inference**: feed function bytes + caller context, ask LLM to suggest a likely struct layout. Validate by reapplying and rerunning decompile.
3. **Pseudocode commenting**: take decompiled C, ask LLM to add inline comments explaining each statement.
4. **Library function recognition by behavior**: instead of byte-pattern FunctionID, ask LLM "this looks like libc.sprintf because... ".
5. **Algorithm recognition**: "this function looks like AES key expansion" → mark as such.
6. **Decompiler hint generator**: when Ghidra's decompile output is unreadable, LLM rewrites it for readability without changing semantics (verifier checks behavioral equivalence on toy inputs).
7. **Vulnerability suggestion**: feed a function decompile, ask "any obvious memory safety / TOCTOU / integer overflow / format string bugs?".
8. **Patch suggestion**: given a vuln, LLM proposes a binary patch.
9. **Cross-binary semantic similarity**: embed every function's decompile, do vector search to find "similar functions in other binaries".
10. **Conversational reverse engineering**: chat panel that has the current function loaded as context.
11. **From natural-language to script**: "rename all functions that look like getters" → generates a script automatically.

## Implementation phases

**Phase 0 (month 0-2): foundation**
- Lancer "RE" tab in the existing Svelte UI
- Project model: ingest a binary, store in SQLite (`redb` if you want pure Rust)
- ELF + PE loader via `goblin`
- Section/segment view, hexdump pane

**Phase 1 (month 2-5): disassembler MVP (x86_64)**
- iced-x86 integration for disassembly
- Function start detection: symbol table + entry point + prologue heuristics
- Cross-reference index (call and data refs)
- Linear listing UI
- Function navigator
- Rename symbols
- Comments
- Strings extraction

**Phase 2 (month 5-8): graph + types + ARM**
- Basic block computation, function graph view (CFG)
- Call graph view
- Simple data type system (no full C parsing yet — just int8/int16/int32/struct via JSON)
- ARM64 disassembly via `bad64` or `disarm64`
- Demangling (cpp_demangle, rustc-demangle, msvc-demangler)

**Phase 3 (month 8-12): AI decompiler pane**
- Lift to a simple custom IR (per arch lifters)
- LLM-based decompilation: send disassembly + context to model, render pseudocode
- Naming/typing suggestions
- Conversational pane (chat with the function loaded)

**Phase 4 (month 12-18): scripting + headless**
- Embed `rhai` or `mlua` for scripting, plus Python via `pyo3` if you want CPython interop
- CLI mode: `lancer re analyze binary.elf --script x.rhai --output report.json`
- DWARF support via `gimli`
- PDB support via `pdb`

**Phase 5 (month 18-30): real decompiler (the long road)**
- Either: wrap Ghidra's `decompile` binary as subprocess and ship it (Apache 2.0, totally OK)
- Or: integrate `retdec` via FFI
- Or: invest in writing your own — multi-year, write a paper

**Skip indefinitely**: Sleigh-compatible compiler, project server, P-code emulator, GUI parity with Ghidra. None of these win bug bounty work.

## Alternative: wrap instead of clone

The honest play:
- **Lancer RE = Ghidra in a window** — ship Ghidra headless as a subprocess (Apache 2.0, ship it), drive it via `analyzeHeadless` for ingest + analysis, parse the resulting GZF/JSON, render everything in your Svelte UI. Add AI panels. This is what Cutter does for radare2 — that's a viable model. Ships in 2-4 months. Real users.
- **Or**: integrate via `r2pipe` against radare2 for disasm + use r2dec for decompile. Lighter, no JVM. Worse decompile quality.
- **Or**: pure Rust, no decompiler v1, plus LLM-decompile pane. Bet on AI decompilation maturing. Ships in 6-9 months. Differentiated story.

**Recommendation**: option 3 (pure Rust + AI decompile). Aligns with where the field is going (AI-first RE tools), fits a solo dev timeline, gives you a clean Rust binary distribution story Ghidra cannot match, and the "Lancer is the AI-native Ghidra" pitch writes itself.

---

## GUI (Lancer-standard pattern)

`lancer-ghidra` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-ghidra-cli` companion binary), but the **plain `lancer-ghidra` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-ghidra/`, `%APPDATA%\lancer-ghidra\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-ghidra-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-ghidra.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-ghidra.exe` (double-click opens the GUI window).
- Linux: `build/lancer-ghidra` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-ghidra` (bundled into `lancer-ghidra.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-ghidra/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-ghidra.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-ghidra-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-ghidra
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-ghidra.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-ghidra-windows-x86_64\bin\lancer-ghidra.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-ghidra`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
