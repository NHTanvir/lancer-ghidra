//! lancer-ghidra
//!
//! Rust clone of NSA's Ghidra — software reverse engineering CLI.
//! See plan.md (local, gitignored) for the long-form blueprint.

mod ai;
mod analysis;
mod cfg;
mod db;
mod debuginfo;
mod demangle;
mod disasm;
mod functions;
mod hexdump;
mod ir;
mod llm;
mod loader;
mod loaders_extra;
mod script;
mod strings;
mod web;
mod xref;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "lancer-ghidra",
    version,
    about = "Rust clone of NSA's Ghidra — disassembler + binary analyzer",
    long_about = "Loads ELF/PE/Mach-O/raw/Intel-HEX/SREC/WASM binaries and \
                  exposes Ghidra-style views: sections, symbols, strings, \
                  hexdump, disassembly, function detection, cross-references, \
                  CFG, call graph, stack analysis, parameter ID, constant \
                  propagation, FunctionID hashing. Annotation state (renames, \
                  comments, types) is persisted in a project DB next to the \
                  binary. Phase 3 'AI decompiler' assembles a prompt blob and \
                  can POST it live to Anthropic's API with --send. Phase 4 \
                  scripting is a `rhai` host with a Ghidra-style API. Bonus: \
                  built-in localhost web UI via `lancer-ghidra web`."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum InputFormat {
    Auto,
    Raw,
    IntelHex,
    Srec,
    Wasm,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliArch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Mips,
    PowerPc,
    RiscV,
    Unknown,
}

impl From<CliArch> for loader::Arch {
    fn from(a: CliArch) -> Self {
        match a {
            CliArch::X86 => loader::Arch::X86,
            CliArch::X86_64 => loader::Arch::X86_64,
            CliArch::Arm => loader::Arch::Arm,
            CliArch::Aarch64 => loader::Arch::Aarch64,
            CliArch::Mips => loader::Arch::Mips,
            CliArch::PowerPc => loader::Arch::PowerPc,
            CliArch::RiscV => loader::Arch::RiscV,
            CliArch::Unknown => loader::Arch::Unknown,
        }
    }
}

#[derive(clap::Args, Debug)]
struct BinArg {
    /// Path to the binary to analyze.
    binary: PathBuf,

    /// Override the input format (otherwise detected from goblin / extension).
    #[arg(long, default_value = "auto", global = true)]
    format: InputFormat,

    /// Architecture for raw / Intel-HEX / SREC formats.
    #[arg(long, default_value = "x86-64", global = true)]
    arch: CliArch,

    /// Base address for raw / Intel-HEX / SREC formats.
    #[arg(long, default_value = "0", value_parser = parse_u64, global = true)]
    base: u64,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print binary metadata (format, arch, entry, image base, library deps).
    Info(BinArg),

    /// List sections / segments with file offsets and permissions.
    Sections(BinArg),

    /// List symbols (with demangling). Includes DWARF / PDB symbols if present.
    Symbols {
        #[command(flatten)]
        bin: BinArg,
        #[arg(long)]
        pdb: Option<PathBuf>,
        #[arg(long)]
        raw: bool,
    },

    /// Extract printable ASCII + UTF-16LE strings.
    Strings {
        #[command(flatten)]
        bin: BinArg,
        #[arg(short = 'n', long, default_value_t = strings::DEFAULT_MIN_LEN)]
        min_len: usize,
    },

    /// Hexdump a range of the binary by virtual address.
    Hexdump {
        #[command(flatten)]
        bin: BinArg,
        #[arg(value_parser = parse_u64)]
        address: u64,
        #[arg(default_value_t = 256, value_parser = parse_u64)]
        length: u64,
    },

    /// Disassemble starting at an address (or a function name).
    Disasm {
        #[command(flatten)]
        bin: BinArg,
        target: String,
        #[arg(long, default_value_t = 256, value_parser = parse_u64)]
        length: u64,
    },

    /// Detect functions and print them (entry, size, name, source).
    Functions {
        #[command(flatten)]
        bin: BinArg,
        #[arg(long)]
        no_prologue: bool,
    },

    /// Show cross-references to an address (or function).
    Xrefs {
        #[command(flatten)]
        bin: BinArg,
        target: String,
    },

    /// Emit the control flow graph for a function as Graphviz DOT.
    Cfg {
        #[command(flatten)]
        bin: BinArg,
        target: String,
    },

    /// Emit the project-wide call graph as DOT or JSON.
    Callgraph {
        #[command(flatten)]
        bin: BinArg,
        #[arg(long)]
        json: bool,
    },

    /// Lift a function to the Simple-IR and print it.
    Ir {
        #[command(flatten)]
        bin: BinArg,
        target: String,
    },

    /// Recover stack frame info: locals, frame size, fp usage.
    Stack {
        #[command(flatten)]
        bin: BinArg,
        target: String,
    },

    /// Recover parameter registers used by a function.
    Params {
        #[command(flatten)]
        bin: BinArg,
        target: String,
    },

    /// Cheap constant propagation: track immediates flowing through registers.
    Constprop {
        #[command(flatten)]
        bin: BinArg,
        target: String,
    },

    /// Hash each function's relocation-masked bytes (FunctionID).
    Funcid {
        #[command(flatten)]
        bin: BinArg,
        /// Write the fingerprint DB to JSON.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Load an existing fingerprint DB to match this binary against.
        #[arg(long)]
        r#match: Option<PathBuf>,
    },

    /// Build an LLM-decompile prompt for a function and print it.
    AiDecompile {
        #[command(flatten)]
        bin: BinArg,
        target: String,
        #[arg(long)]
        out: Option<PathBuf>,
        /// POST the prompt to Anthropic (requires ANTHROPIC_API_KEY).
        #[arg(long)]
        send: bool,
        #[arg(long, default_value = "claude-opus-4-7")]
        model: String,
    },

    /// Run a `.rhai` script against the binary. See README for the API.
    Script {
        #[command(flatten)]
        bin: BinArg,
        script_path: PathBuf,
    },

    /// Rename a function or symbol (persisted in the project DB).
    Rename {
        #[command(flatten)]
        bin: BinArg,
        #[arg(value_parser = parse_u64)]
        address: u64,
        name: String,
    },

    /// Add or replace a comment on an address.
    Comment {
        #[command(flatten)]
        bin: BinArg,
        #[arg(value_parser = parse_u64)]
        address: u64,
        text: String,
    },

    /// Define or assign data types.
    Type {
        #[command(flatten)]
        bin: BinArg,
        #[command(subcommand)]
        op: TypeOp,
    },

    /// List all annotations stored in the project DB for this binary.
    Annotations(BinArg),

    /// Run a full headless analysis and emit JSON (includes annotations).
    Analyze {
        #[command(flatten)]
        bin: BinArg,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        pdb: Option<PathBuf>,
        /// Optional Rhai script to run after analysis (receives `ctx` API).
        #[arg(long)]
        script: Option<PathBuf>,
    },

    /// Spawn a localhost web UI.
    Web {
        #[command(flatten)]
        bin: BinArg,
        #[arg(long, default_value = "127.0.0.1:7474")]
        addr: String,
    },
}

#[derive(Subcommand, Debug)]
enum TypeOp {
    /// Add an int type: --name u32 --size 4 --signed false
    AddInt {
        #[arg(long)]
        name: String,
        #[arg(long)]
        size: u8,
        #[arg(long, default_value_t = false)]
        signed: bool,
    },
    /// Add a pointer type.
    AddPointer {
        #[arg(long)]
        name: String,
        #[arg(long)]
        target: String,
    },
    /// Assign a type to an address.
    Apply {
        #[arg(value_parser = parse_u64)]
        address: u64,
        type_name: String,
    },
    /// List type definitions.
    List,
}

fn parse_u64(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(stripped, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Info(b) => cmd_info(&b),
        Commands::Sections(b) => cmd_sections(&b),
        Commands::Symbols { bin, pdb, raw } => cmd_symbols(&bin, pdb.as_deref(), raw),
        Commands::Strings { bin, min_len } => cmd_strings(&bin, min_len),
        Commands::Hexdump { bin, address, length } => cmd_hexdump(&bin, address, length),
        Commands::Disasm { bin, target, length } => cmd_disasm(&bin, &target, length),
        Commands::Functions { bin, no_prologue } => cmd_functions(&bin, no_prologue),
        Commands::Xrefs { bin, target } => cmd_xrefs(&bin, &target),
        Commands::Cfg { bin, target } => cmd_cfg(&bin, &target),
        Commands::Callgraph { bin, json } => cmd_callgraph(&bin, json),
        Commands::Ir { bin, target } => cmd_ir(&bin, &target),
        Commands::Stack { bin, target } => cmd_stack(&bin, &target),
        Commands::Params { bin, target } => cmd_params(&bin, &target),
        Commands::Constprop { bin, target } => cmd_constprop(&bin, &target),
        Commands::Funcid { bin, out, r#match } => cmd_funcid(&bin, out.as_deref(), r#match.as_deref()),
        Commands::AiDecompile { bin, target, out, send, model } => {
            cmd_ai_decompile(&bin, &target, out.as_deref(), send, &model)
        }
        Commands::Script { bin, script_path } => cmd_script(&bin, &script_path),
        Commands::Rename { bin, address, name } => cmd_rename(&bin, address, &name),
        Commands::Comment { bin, address, text } => cmd_comment(&bin, address, &text),
        Commands::Type { bin, op } => cmd_type(&bin, op),
        Commands::Annotations(b) => cmd_annotations(&b),
        Commands::Analyze { bin, out, pdb, script } => cmd_analyze(&bin, out.as_deref(), pdb.as_deref(), script.as_deref()),
        Commands::Web { bin, addr } => cmd_web(&bin, &addr),
    }
}

// ---------- loading ----------

fn load_binary(b: &BinArg) -> Result<loader::Binary> {
    let bytes = std::fs::read(&b.binary)?;
    let fmt = match b.format {
        InputFormat::Auto => detect_format(&b.binary, &bytes),
        other => other,
    };
    match fmt {
        InputFormat::Auto => loader::Binary::from_bytes(b.binary.clone(), bytes),
        InputFormat::Raw => Ok(loaders_extra::load_raw(b.binary.clone(), bytes, b.arch.into(), b.base)),
        InputFormat::IntelHex => {
            let text = std::str::from_utf8(&bytes)?.to_string();
            loaders_extra::load_intel_hex(b.binary.clone(), &text, b.arch.into())
        }
        InputFormat::Srec => {
            let text = std::str::from_utf8(&bytes)?.to_string();
            loaders_extra::load_srec(b.binary.clone(), &text, b.arch.into())
        }
        InputFormat::Wasm => loaders_extra::load_wasm(b.binary.clone(), bytes),
    }
}

fn detect_format(path: &Path, bytes: &[u8]) -> InputFormat {
    if bytes.len() >= 4 && &bytes[..4] == b"\0asm" {
        return InputFormat::Wasm;
    }
    match path.extension().and_then(|s| s.to_str()) {
        Some("hex" | "ihex") => InputFormat::IntelHex,
        Some("srec" | "s19" | "s28" | "s37" | "mot") => InputFormat::Srec,
        Some("wasm") => InputFormat::Wasm,
        Some("bin") => InputFormat::Raw,
        _ => InputFormat::Auto,
    }
}

// ---------- commands ----------

fn cmd_info(b: &BinArg) -> Result<()> {
    let bin = load_binary(b)?;
    println!("path        : {}", bin.path.display());
    println!("format      : {:?}", bin.format);
    println!("arch        : {}", bin.arch.as_str());
    println!("endian      : {:?}", bin.endian);
    println!("entry       : {:#x}", bin.entry);
    println!("image base  : {:#x}", bin.image_base);
    println!("sections    : {}", bin.sections.len());
    println!("symbols     : {}", bin.symbols.len());
    println!("imports     : {}", bin.imports.len());
    println!("exports     : {}", bin.exports.len());
    if !bin.libraries.is_empty() {
        println!("libraries   :");
        for l in &bin.libraries {
            println!("  - {}", l);
        }
    }
    Ok(())
}

fn cmd_sections(b: &BinArg) -> Result<()> {
    let bin = load_binary(b)?;
    println!("{:<24}  {:>16}  {:>10}  {:>10}  perms", "name", "vaddr", "size", "file_off");
    println!("{}", "-".repeat(80));
    for s in &bin.sections {
        let mut perms = String::new();
        perms.push(if s.readable { 'r' } else { '-' });
        perms.push(if s.writable { 'w' } else { '-' });
        perms.push(if s.executable { 'x' } else { '-' });
        println!("{:<24}  {:>#16x}  {:>#10x}  {:>#10x}  {}",
            truncate(&s.name, 24), s.vaddr, s.size, s.file_offset, perms);
    }
    Ok(())
}

fn cmd_symbols(b: &BinArg, pdb_path: Option<&Path>, raw: bool) -> Result<()> {
    let mut bin = load_binary(b)?;
    if let Ok(extra) = debuginfo::load_dwarf_symbols(&bin) {
        bin.symbols.extend(extra);
    }
    if let Some(p) = pdb_path {
        if let Ok(extra) = debuginfo::load_pdb_symbols(p, bin.image_base) {
            bin.symbols.extend(extra);
        }
    }

    let mut seen = std::collections::HashSet::new();
    let mut printed = 0;
    println!("{:>16}  {:<8}  {}", "address", "kind", "name");
    println!("{}", "-".repeat(72));
    for s in &bin.symbols {
        if !seen.insert((s.address, s.name.clone())) {
            continue;
        }
        let kind = format!("{:?}", s.kind);
        let demangled = if raw { None } else { demangle::demangle(&s.name) };
        let shown = demangled.as_deref().unwrap_or(s.name.as_str());
        println!("{:>#16x}  {:<8}  {}", s.address, kind, shown);
        printed += 1;
    }
    eprintln!("({} symbols)", printed);
    Ok(())
}

fn cmd_strings(b: &BinArg, min_len: usize) -> Result<()> {
    let bin = load_binary(b)?;
    let strs = strings::extract(&bin, min_len);
    for s in &strs {
        let enc = match s.encoding {
            strings::Encoding::Ascii => "a",
            strings::Encoding::Utf16Le => "w",
        };
        println!("{:#016x} [{}] {}", s.vaddr, enc, s.value);
    }
    eprintln!("({} strings)", strs.len());
    Ok(())
}

fn cmd_hexdump(b: &BinArg, address: u64, length: u64) -> Result<()> {
    let bin = load_binary(b)?;
    let bytes = bin.read_va(address, length as usize)
        .ok_or_else(|| anyhow!("address {:#x} not mapped", address))?;
    print!("{}", hexdump::render(address, bytes));
    Ok(())
}

fn cmd_disasm(b: &BinArg, target: &str, length: u64) -> Result<()> {
    let bin = load_binary(b)?;
    let (addr, function_size) = resolve_target(&bin, target)?;
    let len = function_size.unwrap_or(length).max(4);
    let insns = disasm::disassemble_va(&bin, addr, len as usize)?;
    for ins in &insns {
        let bytes_hex: String = ins.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        println!("{:>#16x}: {:<24} {}", ins.address, bytes_hex, ins.text);
    }
    Ok(())
}

fn cmd_functions(b: &BinArg, no_prologue: bool) -> Result<()> {
    let mut bin = load_binary(b)?;
    if let Ok(extra) = debuginfo::load_dwarf_symbols(&bin) {
        bin.symbols.extend(extra);
    }
    let opts = functions::AnalysisOptions {
        use_prologue_scan: !no_prologue,
        ..Default::default()
    };
    let funcs = functions::analyze(&bin, &opts);

    let annotations = try_open_db(&bin).and_then(|db| db.snapshot().ok()).unwrap_or_default();

    println!("{:>16}  {:>10}  {:<10}  name", "entry", "size", "source");
    println!("{}", "-".repeat(72));
    for f in &funcs {
        let pretty = annotations.renames.get(&f.entry)
            .cloned()
            .or_else(|| demangle::demangle(&f.name))
            .unwrap_or_else(|| f.name.clone());
        println!("{:>#16x}  {:>#10x}  {:<10}  {}", f.entry, f.size, format!("{:?}", f.source), pretty);
    }
    eprintln!("({} functions)", funcs.len());
    Ok(())
}

fn cmd_xrefs(b: &BinArg, target: &str) -> Result<()> {
    let (bin, funcs, xrefs, _strs, by_addr) = full_analysis(b, None)?;
    let (addr, _) = resolve_target_with_names(&bin, &by_addr, target)?;
    let to = xrefs.references_to(addr);
    let from = xrefs.references_from(addr);
    let names = name_lookup(&funcs);

    println!("references TO {:#x} ({}):", addr, to.len());
    for f in &to {
        let owner = names.get(f).cloned().unwrap_or_else(|| "?".to_string());
        println!("  {:#x}  in  {}", f, owner);
    }
    println!();
    println!("references FROM {:#x} ({}):", addr, from.len());
    for t in &from {
        let owner = names.get(t).cloned().unwrap_or_else(|| "?".to_string());
        println!("  -> {:#x}  {}", t, owner);
    }
    Ok(())
}

fn cmd_cfg(b: &BinArg, target: &str) -> Result<()> {
    let (bin, funcs, _xrefs, _strs, by_addr) = full_analysis(b, None)?;
    let (addr, _) = resolve_target_with_names(&bin, &by_addr, target)?;
    let f = funcs.iter().find(|f| f.entry == addr)
        .ok_or_else(|| anyhow!("no function with entry {:#x}", addr))?;
    let bytes = bin.read_va(f.entry, f.size as usize)
        .ok_or_else(|| anyhow!("function bytes unmapped"))?;
    let insns = disasm::disassemble(bin.arch, f.entry, bytes)?;
    let cfg = cfg::build_cfg(f.entry, &insns);
    println!("{}", cfg.to_dot());
    Ok(())
}

fn cmd_callgraph(b: &BinArg, json: bool) -> Result<()> {
    let (_bin, funcs, _xrefs, _strs, _by_addr) = full_analysis(b, None)?;
    let cg = cfg::build_call_graph(&funcs);
    if json {
        println!("{}", serde_json::to_string_pretty(&cg.to_json())?);
    } else {
        println!("{}", cg.to_dot());
    }
    Ok(())
}

fn cmd_ir(b: &BinArg, target: &str) -> Result<()> {
    let (bin, funcs, _x, _s, by_addr) = full_analysis(b, None)?;
    let (addr, _) = resolve_target_with_names(&bin, &by_addr, target)?;
    let f = funcs.iter().find(|f| f.entry == addr)
        .ok_or_else(|| anyhow!("no function with entry {:#x}", addr))?;
    let bytes = bin.read_va(f.entry, f.size as usize).ok_or_else(|| anyhow!("function bytes unmapped"))?;
    let insns = disasm::disassemble(bin.arch, f.entry, bytes)?;
    let lifted = ir::lift(bin.arch, &insns);
    for li in &lifted {
        println!("{:>#16x}  {}", li.address, li.mnemonic);
        for op in &li.ops {
            println!("    {:?}", op);
        }
    }
    Ok(())
}

fn cmd_stack(b: &BinArg, target: &str) -> Result<()> {
    let (bin, funcs, _x, _s, by_addr) = full_analysis(b, None)?;
    let (addr, _) = resolve_target_with_names(&bin, &by_addr, target)?;
    let f = funcs.iter().find(|f| f.entry == addr)
        .ok_or_else(|| anyhow!("no function with entry {:#x}", addr))?;
    let bytes = bin.read_va(f.entry, f.size as usize).ok_or_else(|| anyhow!("function bytes unmapped"))?;
    let insns = disasm::disassemble(bin.arch, f.entry, bytes)?;
    let frame = analysis::analyze_stack(bin.arch, f.entry, &insns);
    println!("function          : {:#x} ({})", frame.function, f.name);
    println!("frame size        : {}", frame.frame_size);
    println!("uses frame ptr    : {}", frame.uses_frame_pointer);
    println!("locals ({}):", frame.locals.len());
    for v in &frame.locals {
        println!("  offset {:>+6}  size {:>2}  accesses {}", v.offset, v.size, v.access_count);
    }
    Ok(())
}

fn cmd_params(b: &BinArg, target: &str) -> Result<()> {
    let (bin, funcs, _x, _s, by_addr) = full_analysis(b, None)?;
    let (addr, _) = resolve_target_with_names(&bin, &by_addr, target)?;
    let f = funcs.iter().find(|f| f.entry == addr)
        .ok_or_else(|| anyhow!("no function with entry {:#x}", addr))?;
    let bytes = bin.read_va(f.entry, f.size as usize).ok_or_else(|| anyhow!("function bytes unmapped"))?;
    let insns = disasm::disassemble(bin.arch, f.entry, bytes)?;
    let lifted = ir::lift(bin.arch, &insns);
    let cc = analysis::detect_calling_convention(&bin);
    let p = analysis::recover_parameters(cc, f.entry, &lifted);
    println!("function   : {:#x} ({})", f.entry, f.name);
    println!("convention : {:?}", p.convention);
    println!("args used  : {:?}", p.args_used);
    Ok(())
}

fn cmd_constprop(b: &BinArg, target: &str) -> Result<()> {
    let (bin, funcs, _x, _s, by_addr) = full_analysis(b, None)?;
    let (addr, _) = resolve_target_with_names(&bin, &by_addr, target)?;
    let f = funcs.iter().find(|f| f.entry == addr)
        .ok_or_else(|| anyhow!("no function with entry {:#x}", addr))?;
    let bytes = bin.read_va(f.entry, f.size as usize).ok_or_else(|| anyhow!("function bytes unmapped"))?;
    let insns = disasm::disassemble(bin.arch, f.entry, bytes)?;
    let consts = analysis::propagate_constants(bin.arch, &insns);
    println!("{:>16}  {:<8}  value", "address", "reg");
    println!("{}", "-".repeat(50));
    for c in &consts {
        println!("{:>#16x}  {:<8}  {:#x}", c.address, c.register, c.value);
    }
    eprintln!("({} const observations)", consts.len());
    Ok(())
}

fn cmd_funcid(b: &BinArg, out: Option<&Path>, match_path: Option<&Path>) -> Result<()> {
    let (bin, funcs, _x, _s, _by_addr) = full_analysis(b, None)?;
    let fps = analysis::fingerprint_all(&funcs, &bin);

    if let Some(p) = match_path {
        let text = std::fs::read_to_string(p)?;
        let known: Vec<KnownFunc> = serde_json::from_str(&text)?;
        let by_hash: HashMap<String, &str> = known.iter().map(|k| (k.masked_hash.clone(), k.name.as_str())).collect();
        let mut matched = 0;
        for fp in &fps {
            if let Some(name) = by_hash.get(&fp.masked_hash) {
                println!("{:#x}  ->  {}", fp.function, name);
                matched += 1;
            }
        }
        eprintln!("({} / {} matched)", matched, fps.len());
        return Ok(());
    }

    let exports: Vec<KnownFunc> = fps.iter().zip(funcs.iter())
        .map(|(fp, f)| KnownFunc {
            name: f.name.clone(),
            masked_hash: fp.masked_hash.clone(),
            size: fp.size,
        })
        .collect();
    let json = serde_json::to_string_pretty(&exports)?;
    if let Some(p) = out {
        std::fs::write(p, &json)?;
        eprintln!("wrote {} fingerprints to {}", exports.len(), p.display());
    } else {
        println!("{}", json);
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KnownFunc {
    name: String,
    masked_hash: String,
    size: u64,
}

fn cmd_ai_decompile(b: &BinArg, target: &str, out: Option<&Path>, send: bool, model: &str) -> Result<()> {
    let (bin, funcs, xrefs, strs, by_addr) = full_analysis(b, None)?;
    let (addr, _) = resolve_target_with_names(&bin, &by_addr, target)?;
    let f = funcs.iter().find(|f| f.entry == addr)
        .ok_or_else(|| anyhow!("no function with entry {:#x}", addr))?;
    let bytes = bin.read_va(f.entry, f.size as usize).ok_or_else(|| anyhow!("function bytes unmapped"))?;
    let insns = disasm::disassemble(bin.arch, f.entry, bytes)?;
    let prompt = ai::build_prompt(&ai::DecompileContext {
        bin: &bin,
        func: f,
        insns: &insns,
        xrefs: &xrefs,
        all_strings: &strs,
        all_functions: &funcs,
    });

    if send {
        let mut cfg = llm::LlmConfig::default();
        cfg.model = model.to_string();
        let reply = llm::send_prompt(&prompt, &cfg)?;
        if let Some(p) = out {
            std::fs::write(p, reply)?;
        } else {
            println!("{}", reply);
        }
    } else if let Some(p) = out {
        std::fs::write(p, prompt)?;
        eprintln!("wrote prompt to {}", p.display());
    } else {
        print!("{}", prompt);
    }
    Ok(())
}

fn cmd_script(b: &BinArg, script_path: &Path) -> Result<()> {
    let bin = load_binary(b)?;
    let db = db::ProjectDb::open(&bin.path, &bin.bytes).ok();
    script::run_script(script_path, bin, db)
}

fn cmd_rename(b: &BinArg, address: u64, name: &str) -> Result<()> {
    let bin = load_binary(b)?;
    let db = db::ProjectDb::open(&bin.path, &bin.bytes)?;
    db.set_rename(address, name)?;
    eprintln!("renamed {:#x} -> {}", address, name);
    Ok(())
}

fn cmd_comment(b: &BinArg, address: u64, text: &str) -> Result<()> {
    let bin = load_binary(b)?;
    let db = db::ProjectDb::open(&bin.path, &bin.bytes)?;
    db.set_comment(address, text)?;
    eprintln!("comment on {:#x} -> {}", address, text);
    Ok(())
}

fn cmd_type(b: &BinArg, op: TypeOp) -> Result<()> {
    let bin = load_binary(b)?;
    let db = db::ProjectDb::open(&bin.path, &bin.bytes)?;
    match op {
        TypeOp::AddInt { name, size, signed } => {
            db.add_type_definition(&db::TypeDef {
                name: name.clone(),
                kind: db::TypeKind::Int { size, signed },
            })?;
            eprintln!("added int type {}", name);
        }
        TypeOp::AddPointer { name, target } => {
            db.add_type_definition(&db::TypeDef {
                name: name.clone(),
                kind: db::TypeKind::Pointer { target },
            })?;
            eprintln!("added pointer type {}", name);
        }
        TypeOp::Apply { address, type_name } => {
            db.set_type_assignment(address, &type_name)?;
            eprintln!("{:#x} -> {}", address, type_name);
        }
        TypeOp::List => {
            let snap = db.snapshot()?;
            for (name, def) in &snap.type_definitions {
                println!("{}  {:?}", name, def.kind);
            }
        }
    }
    Ok(())
}

fn cmd_annotations(b: &BinArg) -> Result<()> {
    let bin = load_binary(b)?;
    let db = db::ProjectDb::open(&bin.path, &bin.bytes)?;
    let snap = db.snapshot()?;
    println!("# Renames ({}):", snap.renames.len());
    for (addr, name) in &snap.renames {
        println!("  {:#x}  {}", addr, name);
    }
    println!("# Comments ({}):", snap.comments.len());
    for (addr, text) in &snap.comments {
        println!("  {:#x}  {}", addr, text);
    }
    println!("# Type assignments ({}):", snap.type_assignments.len());
    for (addr, ty) in &snap.type_assignments {
        println!("  {:#x}  {}", addr, ty);
    }
    println!("# Type definitions ({}):", snap.type_definitions.len());
    for (name, def) in &snap.type_definitions {
        println!("  {}  {:?}", name, def.kind);
    }
    Ok(())
}

fn cmd_analyze(b: &BinArg, out: Option<&Path>, pdb_path: Option<&Path>, script_path: Option<&Path>) -> Result<()> {
    let (bin, funcs, xrefs, strs, _by_addr) = full_analysis(b, pdb_path)?;

    let annotations = db::ProjectDb::open(&bin.path, &bin.bytes)
        .and_then(|db| db.snapshot())
        .ok()
        .unwrap_or_default();

    let report = serde_json::json!({
        "path": bin.path.display().to_string(),
        "format": format!("{:?}", bin.format),
        "arch": bin.arch.as_str(),
        "endian": format!("{:?}", bin.endian),
        "entry": bin.entry,
        "image_base": bin.image_base,
        "sections": bin.sections,
        "imports": bin.imports,
        "exports": bin.exports,
        "libraries": bin.libraries,
        "functions": funcs,
        "strings": strs,
        "xrefs": xrefs.edges.iter().collect::<Vec<_>>(),
        "annotations": annotations,
    });

    let json = serde_json::to_string_pretty(&report)?;
    if let Some(p) = out {
        std::fs::write(p, &json)?;
        eprintln!("wrote analysis to {}", p.display());
    } else {
        println!("{}", json);
    }

    if let Some(sp) = script_path {
        eprintln!("running script {}…", sp.display());
        let db = db::ProjectDb::open(&bin.path, &bin.bytes).ok();
        script::run_script(sp, bin, db)?;
    }

    Ok(())
}

fn cmd_web(b: &BinArg, addr: &str) -> Result<()> {
    let bin = load_binary(b)?;
    web::serve(bin, addr)
}

// ---------- helpers ----------

type FullAnalysis = (
    loader::Binary,
    Vec<functions::Function>,
    xref::XrefIndex,
    Vec<strings::FoundString>,
    HashMap<String, u64>,
);

fn try_open_db(bin: &loader::Binary) -> Option<db::ProjectDb> {
    db::ProjectDb::open(&bin.path, &bin.bytes).ok()
}

fn full_analysis(b: &BinArg, pdb_path: Option<&Path>) -> Result<FullAnalysis> {
    let mut bin = load_binary(b)?;

    if let Ok(extra) = debuginfo::load_dwarf_symbols(&bin) {
        bin.symbols.extend(extra);
    }
    if let Some(p) = pdb_path {
        if let Ok(extra) = debuginfo::load_pdb_symbols(p, bin.image_base) {
            bin.symbols.extend(extra);
        }
    }

    let mut funcs = functions::analyze(&bin, &functions::AnalysisOptions::default());

    // Apply persisted renames before names get cached anywhere.
    let snapshot = try_open_db(&bin).and_then(|db| db.snapshot().ok()).unwrap_or_default();
    for f in &mut funcs {
        if let Some(name) = snapshot.renames.get(&f.entry) {
            f.name = name.clone();
        }
    }

    let mut all_insns: Vec<(functions::Function, Vec<disasm::Insn>)> = Vec::new();
    for f in &funcs {
        if let Some(bytes) = bin.read_va(f.entry, f.size as usize) {
            if let Ok(ins) = disasm::disassemble(bin.arch, f.entry, bytes) {
                all_insns.push((f.clone(), ins));
            }
        }
    }
    let xref_inputs: Vec<(&functions::Function, &[disasm::Insn])> =
        all_insns.iter().map(|(f, v)| (f, v.as_slice())).collect();
    let xrefs = xref::build_index(xref_inputs);

    let strs = strings::extract(&bin, strings::DEFAULT_MIN_LEN);

    let mut by_addr: HashMap<String, u64> = HashMap::new();
    for f in &funcs {
        by_addr.insert(f.name.clone(), f.entry);
        if let Some(d) = demangle::demangle(&f.name) {
            by_addr.insert(d, f.entry);
        }
    }
    for sym in &bin.symbols {
        if sym.address != 0 {
            by_addr.entry(sym.name.clone()).or_insert(sym.address);
        }
    }

    Ok((bin, funcs, xrefs, strs, by_addr))
}

fn resolve_target(bin: &loader::Binary, target: &str) -> Result<(u64, Option<u64>)> {
    if target == "entry" {
        return Ok((bin.entry, None));
    }
    if let Ok(addr) = parse_u64(target) {
        return Ok((addr, None));
    }
    if let Some(sym) = bin.symbols.iter().find(|s| s.name == target) {
        let size = if sym.size > 0 { Some(sym.size) } else { None };
        return Ok((sym.address, size));
    }
    if let Some(exp) = bin.exports.iter().find(|e| e.name == target) {
        return Ok((exp.address, None));
    }
    Err(anyhow!("could not resolve target '{}'", target))
}

fn resolve_target_with_names(
    bin: &loader::Binary,
    by_addr: &HashMap<String, u64>,
    target: &str,
) -> Result<(u64, Option<u64>)> {
    if let Ok((addr, size)) = resolve_target(bin, target) {
        return Ok((addr, size));
    }
    if let Some(&addr) = by_addr.get(target) {
        return Ok((addr, None));
    }
    Err(anyhow!("could not resolve target '{}'", target))
}

fn name_lookup(funcs: &[functions::Function]) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    for f in funcs {
        for addr in f.entry..f.end {
            out.entry(addr).or_insert_with(|| f.name.clone());
        }
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
