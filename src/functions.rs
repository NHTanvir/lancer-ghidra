//! Function boundary detection.
//!
//! Seeds:
//!   1. Symbol table entries of type FUNC
//!   2. Binary entry point
//!   3. PE exports
//! Then refined by:
//!   4. Recursive descent over direct calls
//!   5. (Optional) prologue-pattern linear sweep over executable sections
//!
//! Stripped binaries lose (1), so the prologue scan is what keeps the analysis
//! useful.

use crate::disasm::{disassemble, FlowKind, Insn};
use crate::loader::{Arch, Binary, Section, SymbolKind};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize)]
pub struct Function {
    pub name: String,
    pub entry: u64,
    pub end: u64,
    pub size: u64,
    /// Discovery origin — useful when triaging false positives.
    pub source: Source,
    /// Direct call targets discovered inside this function.
    pub calls: Vec<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Source {
    Symbol,
    Entry,
    Export,
    XrefCall,
    Prologue,
}

pub struct AnalysisOptions {
    pub use_prologue_scan: bool,
    pub max_function_bytes: u64,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            use_prologue_scan: true,
            max_function_bytes: 0x8000, // 32 KiB — large enough for almost any real function
        }
    }
}

/// Discover all functions in the binary.
pub fn analyze(bin: &Binary, opts: &AnalysisOptions) -> Vec<Function> {
    let mut seeds: BTreeMap<u64, (String, Source)> = BTreeMap::new();

    for sym in &bin.symbols {
        if sym.kind == SymbolKind::Function && sym.address != 0 {
            seeds.entry(sym.address)
                .or_insert((sym.name.clone(), Source::Symbol));
        }
    }
    if bin.entry != 0 {
        seeds.entry(bin.entry)
            .or_insert(("entry".to_string(), Source::Entry));
    }
    for exp in &bin.exports {
        seeds.entry(exp.address)
            .or_insert((exp.name.clone(), Source::Export));
    }

    if opts.use_prologue_scan {
        for vaddr in prologue_scan(bin) {
            seeds.entry(vaddr)
                .or_insert((format!("FUN_{:x}", vaddr), Source::Prologue));
        }
    }

    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<(u64, String, Source)> = seeds
        .into_iter()
        .map(|(va, (name, src))| (va, name, src))
        .collect();

    let mut functions: Vec<Function> = Vec::new();
    let mut named: HashMap<u64, String> = HashMap::new();
    // Inclusive-start / exclusive-end intervals of already-covered code.
    let mut covered: Vec<(u64, u64)> = Vec::new();
    let is_covered = |covered: &Vec<(u64, u64)>, addr: u64| -> bool {
        covered.iter().any(|&(s, e)| addr >= s && addr < e)
    };

    while let Some((entry, name, source)) = queue.pop_front() {
        if !visited.insert(entry) {
            continue;
        }
        // Skip prologue/xref candidates that fall inside a function we've already mapped.
        if matches!(source, Source::Prologue | Source::XrefCall) && is_covered(&covered, entry) {
            continue;
        }

        let Some(sect) = bin.section_at(entry) else { continue };
        if !sect.executable {
            continue;
        }

        let max_len = ((sect.vaddr + sect.size) - entry).min(opts.max_function_bytes);
        let Some(slice) = bin.read_va(entry, max_len as usize) else { continue };

        let insns = match disassemble(bin.arch, entry, slice) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let (end_va, calls) = trace_function(&insns, entry, sect);
        covered.push((entry, end_va));

        // Recursive descent: enqueue called functions.
        for &t in &calls {
            if !visited.contains(&t)
                && !is_covered(&covered, t)
                && bin.section_at(t).is_some_and(|s| s.executable)
            {
                queue.push_back((t, format!("FUN_{:x}", t), Source::XrefCall));
            }
        }

        named.insert(entry, name.clone());
        functions.push(Function {
            name,
            entry,
            end: end_va,
            size: end_va.saturating_sub(entry),
            source,
            calls,
        });
    }

    // Re-apply nicer names for any function whose entry matches a known symbol.
    for f in &mut functions {
        if let Some(sym) = bin
            .symbols
            .iter()
            .find(|s| s.address == f.entry && s.kind == SymbolKind::Function)
        {
            f.name = sym.name.clone();
            if f.source == Source::XrefCall || f.source == Source::Prologue {
                f.source = Source::Symbol;
            }
        }
    }

    functions.sort_by_key(|f| f.entry);
    functions
}

/// Walk a linear instruction stream, follow conditional fall-through and local
/// jumps inside the section, and collect direct call targets. Returns
/// (`end_vaddr`, `call_targets`).
fn trace_function(insns: &[Insn], entry: u64, sect: &Section) -> (u64, Vec<u64>) {
    if insns.is_empty() {
        return (entry, Vec::new());
    }

    let addr_to_idx: HashMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, x)| (x.address, i))
        .collect();

    let mut reachable: BTreeSet<usize> = BTreeSet::new();
    let mut stack: Vec<usize> = vec![0];
    let mut calls: Vec<u64> = Vec::new();
    let sect_end = sect.vaddr + sect.size;

    while let Some(idx) = stack.pop() {
        if idx >= insns.len() || !reachable.insert(idx) {
            continue;
        }
        let ins = &insns[idx];

        match ins.flow {
            FlowKind::Call | FlowKind::CallIndirect => {
                if let Some(t) = ins.target {
                    if t != entry {
                        calls.push(t);
                    }
                }
                if idx + 1 < insns.len() {
                    stack.push(idx + 1);
                }
            }
            FlowKind::Jump => {
                if let Some(t) = ins.target {
                    if t >= sect.vaddr && t < sect_end {
                        if let Some(&j) = addr_to_idx.get(&t) {
                            stack.push(j);
                        }
                    }
                }
            }
            FlowKind::CondJump => {
                if let Some(t) = ins.target {
                    if t >= sect.vaddr && t < sect_end {
                        if let Some(&j) = addr_to_idx.get(&t) {
                            stack.push(j);
                        }
                    }
                }
                if idx + 1 < insns.len() {
                    stack.push(idx + 1);
                }
            }
            FlowKind::Return | FlowKind::EndBlock | FlowKind::JumpIndirect => {}
            FlowKind::Sequential => {
                if idx + 1 < insns.len() {
                    stack.push(idx + 1);
                }
            }
        }
    }

    let last_idx = reachable.iter().last().copied().unwrap_or(0);
    let last = &insns[last_idx];
    let end_va = last.address + last.size as u64;
    (end_va, calls)
}

/// Cheap arch-specific prologue scan: walk each executable section in
/// instruction steps, flag addresses whose first instruction matches a known
/// "function start" pattern. Reduces false negatives on stripped binaries.
fn prologue_scan(bin: &Binary) -> Vec<u64> {
    let mut out = Vec::new();
    for sect in bin.code_sections() {
        let bytes = bin.section_bytes(sect);
        if bytes.is_empty() {
            continue;
        }
        match bin.arch {
            Arch::X86_64 | Arch::X86 => scan_x86_prologues(sect.vaddr, bytes, &mut out),
            Arch::Aarch64 => scan_aarch64_prologues(sect.vaddr, bytes, &mut out),
            _ => {}
        }
    }
    out
}

fn scan_x86_prologues(base: u64, bytes: &[u8], out: &mut Vec<u64>) {
    // Prologue bytes:
    //   55                 push rbp
    //   55 48 89 e5        push rbp; mov rbp, rsp
    //   48 83 ec ??        sub rsp, imm8
    //   48 89 e5           mov rbp, rsp
    //   f3 0f 1e fa        endbr64 (CET marker)
    //
    // The CET marker is unique and reliable on its own. For the other patterns we
    // require the candidate to either be 16-byte aligned (typical compiler
    // alignment) or follow a function epilogue byte (0xc3 ret, 0xcb retf), to
    // avoid matching inside the middle of unrelated instructions.
    let mut i = 0;
    while i < bytes.len() {
        let here = &bytes[i..];
        let is_endbr = here.len() >= 4
            && (&here[..4] == [0xf3, 0x0f, 0x1e, 0xfa] || &here[..4] == [0xf3, 0x0f, 0x1e, 0xfb]);

        let is_push_rbp_mov_rbp_rsp = here.len() >= 4
            && here[0] == 0x55
            && here[1] == 0x48
            && here[2] == 0x89
            && here[3] == 0xe5;

        let is_sub_rsp = here.len() >= 4
            && here[0] == 0x48
            && here[1] == 0x83
            && here[2] == 0xec;

        let is_mov_rbp_rsp = here.len() >= 3
            && here[0] == 0x48
            && here[1] == 0x89
            && here[2] == 0xe5;

        if is_endbr {
            out.push(base + i as u64);
            i += 4;
            continue;
        }

        let weaker = is_push_rbp_mov_rbp_rsp || is_sub_rsp || is_mov_rbp_rsp;
        if weaker {
            let aligned = (base + i as u64) % 16 == 0;
            let after_ret = i > 0 && matches!(bytes[i - 1], 0xc3 | 0xcb | 0xcc | 0x90);
            if aligned || after_ret {
                out.push(base + i as u64);
                i += 4;
                continue;
            }
        }

        i += 1;
    }
}

fn scan_aarch64_prologues(base: u64, bytes: &[u8], out: &mut Vec<u64>) {
    // Common aarch64 prologue:
    //   sub sp, sp, #N   (encoded as 0xd10003ff with imm12 in bits 10-21)
    //   stp x29, x30, [sp, #-N]!   (0xa98...) — pre-indexed store pair
    //   stp x29, x30, [sp, #N]     (0xa90...)
    // We do a coarse check on the top byte and bit pattern.
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let word = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        // sub sp, sp, #imm12 : 0b1101_0001_00_imm12_xxxxx_xxxxx ; rd=rn=31
        let is_sub_sp = (word & 0xff_c0_03_ff) == 0xd1_00_03_ff;
        // stp x29, x30, [sp, #imm]!  pre-index, signed offset
        // bits 31..22 = 1010100110, rt=29 (00...11101), rt2=30 (11110), rn=31 (11111)
        let is_stp_fp_lr_preindex = (word & 0xff_c0_7f_ff) == 0xa9_80_7b_ff;
        // stp x29, x30, [sp, #imm]   simple offset
        let is_stp_fp_lr = (word & 0xff_c0_7f_ff) == 0xa9_00_7b_ff;

        if is_sub_sp || is_stp_fp_lr_preindex || is_stp_fp_lr {
            out.push(base + i as u64);
            i += 4;
            continue;
        }
        i += 4;
    }
}
