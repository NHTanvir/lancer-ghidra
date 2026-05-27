//! Higher-level analyses that run on top of the disasm + IR layers:
//!   - stack frame analysis (find frame size from sub/add rsp, identify locals)
//!   - parameter recovery (which arg registers does a function actually read?)
//!   - tiny constant propagation (immediates → registers)
//!
//! All passes are intentionally cheap heuristics: get 80% of the way to
//! something useful without inventing a full data-flow framework. Good enough
//! for the LLM-decompile prompt builder and for the CLI views.

use crate::disasm::{FlowKind, Insn};
use crate::functions::Function;
use crate::ir::{lift, LiftedInsn, Op, Operand};
use crate::loader::{Arch, Binary};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

// ---------- Stack frame ----------

#[derive(Debug, Clone, Serialize)]
pub struct StackFrame {
    pub function: u64,
    pub frame_size: i64,
    pub locals: Vec<StackVar>,
    pub uses_frame_pointer: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackVar {
    pub offset: i64,
    pub size: u8,
    pub access_count: u32,
}

pub fn analyze_stack(arch: Arch, entry: u64, insns: &[Insn]) -> StackFrame {
    let mut frame_size: i64 = 0;
    let mut uses_fp = false;
    let mut accesses: BTreeMap<i64, StackVar> = BTreeMap::new();

    let sp_reg = match arch {
        Arch::X86_64 => "rsp",
        Arch::X86 => "esp",
        Arch::Aarch64 => "sp",
        _ => return StackFrame {
            function: entry,
            frame_size: 0,
            locals: Vec::new(),
            uses_frame_pointer: false,
        },
    };
    let fp_reg = match arch {
        Arch::X86_64 => "rbp",
        Arch::X86 => "ebp",
        Arch::Aarch64 => "x29",
        _ => "",
    };

    let lifted = lift(arch, insns);
    for li in &lifted {
        for op in &li.ops {
            match op {
                Op::Sub { dst: Operand::Reg(r), rhs: Operand::Imm(n), .. } if r == sp_reg => {
                    frame_size = frame_size.max(*n);
                }
                Op::Add { dst: Operand::Reg(r), rhs: Operand::Imm(_n), .. } if r == sp_reg => {
                    // epilogue restore — frame_size already set
                }
                Op::Copy { dst: Operand::Reg(d), src: Operand::Reg(s) }
                    if d == fp_reg && s == sp_reg =>
                {
                    uses_fp = true;
                }
                Op::Load { addr, size, .. } | Op::Store { addr, size, .. } => {
                    if let Some(off) = stack_offset(addr, sp_reg, fp_reg) {
                        let entry = accesses
                            .entry(off)
                            .or_insert_with(|| StackVar { offset: off, size: *size, access_count: 0 });
                        entry.size = entry.size.max(*size);
                        entry.access_count += 1;
                    }
                }
                _ => {}
            }
        }
    }

    StackFrame {
        function: entry,
        frame_size,
        locals: accesses.into_values().collect(),
        uses_frame_pointer: uses_fp,
    }
}

fn stack_offset(addr: &Operand, sp: &str, fp: &str) -> Option<i64> {
    if let Operand::Mem { base: Some(b), disp, .. } = addr {
        if b == sp || (!fp.is_empty() && b == fp) {
            return Some(*disp);
        }
    }
    None
}

// ---------- Parameter recovery ----------

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum CallingConvention {
    Win64,
    SysV64,
    AArch64Aapcs,
    Unknown,
}

pub fn detect_calling_convention(bin: &Binary) -> CallingConvention {
    match (bin.arch, bin.format) {
        (Arch::X86_64, crate::loader::Format::Pe) => CallingConvention::Win64,
        (Arch::X86_64, _) => CallingConvention::SysV64,
        (Arch::Aarch64, _) => CallingConvention::AArch64Aapcs,
        _ => CallingConvention::Unknown,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Parameters {
    pub function: u64,
    pub convention: CallingConvention,
    pub args_used: Vec<String>,
}

/// Walk the lifted ops looking for *reads* of argument-register-equivalents
/// before any write. Anything read first must be a parameter.
pub fn recover_parameters(cc: CallingConvention, entry: u64, lifted: &[LiftedInsn]) -> Parameters {
    let regs = arg_registers(cc);
    let mut used_args: Vec<String> = Vec::new();
    let mut written: BTreeSet<&'static str> = BTreeSet::new();

    for li in lifted {
        for op in &li.ops {
            for reg in &regs {
                if !used_args.iter().any(|x| x == reg) && !written.contains(reg) {
                    if reads_reg(op, reg) {
                        used_args.push((*reg).to_string());
                    }
                }
                if writes_reg(op, reg) {
                    written.insert(reg);
                }
            }
        }
    }

    Parameters {
        function: entry,
        convention: cc,
        args_used: used_args,
    }
}

fn arg_registers(cc: CallingConvention) -> Vec<&'static str> {
    match cc {
        CallingConvention::Win64 => vec!["rcx", "rdx", "r8", "r9"],
        CallingConvention::SysV64 => vec!["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        CallingConvention::AArch64Aapcs => vec!["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        CallingConvention::Unknown => Vec::new(),
    }
}

fn reads_reg(op: &Op, reg: &str) -> bool {
    fn op_reads(o: &Operand, reg: &str) -> bool {
        match o {
            Operand::Reg(r) => r.eq_ignore_ascii_case(reg) || subreg_matches(r, reg),
            Operand::Mem { base, index, .. } => {
                base.as_deref().map_or(false, |b| b.eq_ignore_ascii_case(reg) || subreg_matches(b, reg))
                    || index.as_deref().map_or(false, |i| i.eq_ignore_ascii_case(reg) || subreg_matches(i, reg))
            }
            _ => false,
        }
    }
    match op {
        Op::Copy { src, .. } => op_reads(src, reg),
        Op::Load { addr, .. } => op_reads(addr, reg),
        Op::Store { addr, src, .. } => op_reads(addr, reg) || op_reads(src, reg),
        Op::Add { lhs, rhs, .. }
        | Op::Sub { lhs, rhs, .. }
        | Op::Mul { lhs, rhs, .. }
        | Op::And { lhs, rhs, .. }
        | Op::Or { lhs, rhs, .. }
        | Op::Xor { lhs, rhs, .. }
        | Op::Shl { lhs, rhs, .. }
        | Op::Shr { lhs, rhs, .. }
        | Op::Cmp { lhs, rhs }
        | Op::Test { lhs, rhs } => op_reads(lhs, reg) || op_reads(rhs, reg),
        Op::Push { src } => op_reads(src, reg),
        _ => false,
    }
}

fn writes_reg(op: &Op, reg: &str) -> bool {
    fn dst_matches(o: &Operand, reg: &str) -> bool {
        matches!(o, Operand::Reg(r) if r.eq_ignore_ascii_case(reg) || subreg_matches(r, reg))
    }
    match op {
        Op::Copy { dst, .. }
        | Op::Add { dst, .. }
        | Op::Sub { dst, .. }
        | Op::Mul { dst, .. }
        | Op::And { dst, .. }
        | Op::Or { dst, .. }
        | Op::Xor { dst, .. }
        | Op::Shl { dst, .. }
        | Op::Shr { dst, .. }
        | Op::Load { dst, .. } => dst_matches(dst, reg),
        Op::Pop { dst } => dst_matches(dst, reg),
        _ => false,
    }
}

/// Match e.g. `eax` against `rax` (32-bit subreg of the 64-bit arg register).
fn subreg_matches(reg: &str, full: &str) -> bool {
    let r = reg.to_ascii_lowercase();
    let f = full.to_ascii_lowercase();
    let pairs: &[(&str, &[&str])] = &[
        ("rax", &["eax", "ax", "al", "ah"]),
        ("rbx", &["ebx", "bx", "bl", "bh"]),
        ("rcx", &["ecx", "cx", "cl", "ch"]),
        ("rdx", &["edx", "dx", "dl", "dh"]),
        ("rsi", &["esi", "si", "sil"]),
        ("rdi", &["edi", "di", "dil"]),
        ("rbp", &["ebp", "bp", "bpl"]),
        ("rsp", &["esp", "sp", "spl"]),
        ("r8", &["r8d", "r8w", "r8b"]),
        ("r9", &["r9d", "r9w", "r9b"]),
        ("r10", &["r10d", "r10w", "r10b"]),
        ("r11", &["r11d", "r11w", "r11b"]),
        ("r12", &["r12d", "r12w", "r12b"]),
        ("r13", &["r13d", "r13w", "r13b"]),
        ("r14", &["r14d", "r14w", "r14b"]),
        ("r15", &["r15d", "r15w", "r15b"]),
        ("x0", &["w0"]),
        ("x1", &["w1"]),
        ("x2", &["w2"]),
        ("x3", &["w3"]),
        ("x4", &["w4"]),
        ("x5", &["w5"]),
        ("x6", &["w6"]),
        ("x7", &["w7"]),
    ];
    for (full_name, subs) in pairs {
        if &f == full_name && subs.iter().any(|s| **s == r) {
            return true;
        }
    }
    false
}

// ---------- Constant propagation ----------

#[derive(Debug, Clone, Serialize)]
pub struct ConstValue {
    pub address: u64,
    pub register: String,
    pub value: i64,
}

/// Walk straight through a function, tracking each register's last known
/// constant. Branches reset the state — no joining at control flow merges.
/// This is the Cheap Edition of constant propagation, but it catches the
/// common pattern of `mov eax, 0x1234 ; call X` where the call site reveals
/// what eax was supposed to be.
pub fn propagate_constants(arch: Arch, insns: &[Insn]) -> Vec<ConstValue> {
    let lifted = lift(arch, insns);
    let mut values: HashMap<String, i64> = HashMap::new();
    let mut snapshots: Vec<ConstValue> = Vec::new();

    for li in &lifted {
        for op in &li.ops {
            match op {
                Op::Copy { dst: Operand::Reg(r), src: Operand::Imm(n) } => {
                    values.insert(r.clone(), *n);
                    snapshots.push(ConstValue {
                        address: li.address,
                        register: r.clone(),
                        value: *n,
                    });
                }
                Op::Copy { dst: Operand::Reg(r), src: Operand::Reg(s) } => {
                    if let Some(&v) = values.get(s) {
                        values.insert(r.clone(), v);
                        snapshots.push(ConstValue {
                            address: li.address,
                            register: r.clone(),
                            value: v,
                        });
                    } else {
                        values.remove(r);
                    }
                }
                Op::Xor { dst: Operand::Reg(d), lhs: Operand::Reg(a), rhs: Operand::Reg(b) }
                    if d == a && a == b =>
                {
                    values.insert(d.clone(), 0);
                    snapshots.push(ConstValue {
                        address: li.address,
                        register: d.clone(),
                        value: 0,
                    });
                }
                Op::Add { dst: Operand::Reg(d), lhs: Operand::Reg(s), rhs: Operand::Imm(n) }
                    if d == s =>
                {
                    if let Some(v) = values.get_mut(d) {
                        *v = v.wrapping_add(*n);
                    }
                }
                Op::Sub { dst: Operand::Reg(d), lhs: Operand::Reg(s), rhs: Operand::Imm(n) }
                    if d == s =>
                {
                    if let Some(v) = values.get_mut(d) {
                        *v = v.wrapping_sub(*n);
                    }
                }
                // Any write to a register we can't model invalidates our knowledge.
                Op::Copy { dst: Operand::Reg(r), .. }
                | Op::Add { dst: Operand::Reg(r), .. }
                | Op::Sub { dst: Operand::Reg(r), .. }
                | Op::Mul { dst: Operand::Reg(r), .. }
                | Op::And { dst: Operand::Reg(r), .. }
                | Op::Or { dst: Operand::Reg(r), .. }
                | Op::Shl { dst: Operand::Reg(r), .. }
                | Op::Shr { dst: Operand::Reg(r), .. }
                | Op::Load { dst: Operand::Reg(r), .. }
                | Op::Pop { dst: Operand::Reg(r) } => {
                    values.remove(r);
                }
                Op::Call { .. } => {
                    // Callee may clobber caller-saved regs — be conservative.
                    for r in ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"] {
                        values.remove(r);
                    }
                }
                _ => {}
            }
        }
        // Conservative join: any control flow ends our linear assumption.
        if let Some(last) = insns.last() {
            if last.address == li.address && matches!(last.flow, FlowKind::CondJump | FlowKind::Jump | FlowKind::Return | FlowKind::JumpIndirect) {
                values.clear();
            }
        }
    }

    snapshots
}

// ---------- FunctionID hashing ----------

#[derive(Debug, Clone, Serialize)]
pub struct FunctionFingerprint {
    pub function: u64,
    /// First-N bytes hash (cheap match key).
    pub head_hash: String,
    /// Full function bytes, with branch displacements masked to zero.
    pub masked_hash: String,
    pub size: u64,
}

/// Build a stable hash of a function's bytes, with relative branch/call
/// displacements masked out. Two compiled copies of the same source function
/// (linked at different addresses) should produce the same `masked_hash`.
pub fn fingerprint_function(insns: &[Insn]) -> FunctionFingerprint {
    use sha2::{Digest, Sha256};

    let entry = insns.first().map(|i| i.address).unwrap_or(0);

    let head_size = insns.iter().take(8).map(|i| i.size).sum::<usize>().max(1);
    let head_bytes: Vec<u8> = insns
        .iter()
        .take(8)
        .flat_map(|i| i.bytes.clone())
        .collect();
    let mut h = Sha256::new();
    h.update(&head_bytes);
    let head_hash = hex::encode(h.finalize());

    let masked: Vec<u8> = insns
        .iter()
        .flat_map(|ins| {
            if matches!(
                ins.flow,
                FlowKind::Call | FlowKind::Jump | FlowKind::CondJump
            ) && ins.size >= 4
            {
                // Mask the last 4 bytes (usually the rel32 / b.cond displacement)
                let mut b = ins.bytes.clone();
                let n = b.len();
                if n >= 4 {
                    for byte in &mut b[n - 4..] {
                        *byte = 0;
                    }
                }
                b
            } else {
                ins.bytes.clone()
            }
        })
        .collect();
    let mut h = Sha256::new();
    h.update(&masked);
    let masked_hash = hex::encode(h.finalize());

    let total_size: u64 = insns.iter().map(|i| i.size as u64).sum();

    FunctionFingerprint {
        function: entry,
        head_hash: format!("{}:{}", head_size, head_hash),
        masked_hash,
        size: total_size,
    }
}

/// Project-wide convenience.
pub fn fingerprint_all(funcs: &[Function], bin: &Binary) -> Vec<FunctionFingerprint> {
    use crate::disasm::disassemble;
    let mut out = Vec::new();
    for f in funcs {
        let Some(bytes) = bin.read_va(f.entry, f.size as usize) else { continue };
        let Ok(insns) = disassemble(bin.arch, f.entry, bytes) else { continue };
        out.push(fingerprint_function(&insns));
    }
    out
}
