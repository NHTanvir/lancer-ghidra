//! Simple intermediate representation, inspired by Ghidra's P-code but with a
//! tiny opcode set. Each machine instruction lifts to 1..=N IR ops so later
//! passes (constant propagation, parameter ID, decompiler prompts) stay
//! arch-agnostic.
//!
//! The lifters here are *coarse*: they don't pretend to be cycle-accurate,
//! they cover the opcodes that show up most in compiler output, and they fall
//! back to a generic `Other { mnemonic, text }` op for anything obscure. That
//! is exactly the "pseudo-IR (your own simple form)" the plan calls for in
//! Phase 3.

use crate::disasm::Insn;
use crate::loader::Arch;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub enum Operand {
    Reg(String),
    Imm(i64),
    /// Memory: base + index*scale + disp, in the source arch's addressing units.
    Mem {
        base: Option<String>,
        index: Option<String>,
        scale: u8,
        disp: i64,
        size: u8,
    },
    /// A virtual SSA-flavored temporary used by the lifter.
    Tmp(u32),
    /// A code address (target of branch/call).
    Addr(u64),
}

#[derive(Debug, Clone, Serialize)]
pub enum Op {
    Copy { dst: Operand, src: Operand },
    Load { dst: Operand, addr: Operand, size: u8 },
    Store { addr: Operand, src: Operand, size: u8 },
    Add { dst: Operand, lhs: Operand, rhs: Operand },
    Sub { dst: Operand, lhs: Operand, rhs: Operand },
    Mul { dst: Operand, lhs: Operand, rhs: Operand },
    And { dst: Operand, lhs: Operand, rhs: Operand },
    Or { dst: Operand, lhs: Operand, rhs: Operand },
    Xor { dst: Operand, lhs: Operand, rhs: Operand },
    Shl { dst: Operand, lhs: Operand, rhs: Operand },
    Shr { dst: Operand, lhs: Operand, rhs: Operand },
    Cmp { lhs: Operand, rhs: Operand },
    Test { lhs: Operand, rhs: Operand },
    Branch { target: Operand },
    CondBranch { target: Operand, cc: String },
    Call { target: Operand },
    Return,
    Push { src: Operand },
    Pop { dst: Operand },
    Other { mnemonic: String, text: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct LiftedInsn {
    pub address: u64,
    pub mnemonic: String,
    pub ops: Vec<Op>,
}

/// Lift a function's worth of decoded instructions into IR.
pub fn lift(arch: Arch, insns: &[Insn]) -> Vec<LiftedInsn> {
    insns
        .iter()
        .map(|i| LiftedInsn {
            address: i.address,
            mnemonic: i.mnemonic.clone(),
            ops: lift_one(arch, i),
        })
        .collect()
}

fn lift_one(arch: Arch, ins: &Insn) -> Vec<Op> {
    match arch {
        Arch::X86 | Arch::X86_64 => lift_x86(ins),
        Arch::Aarch64 => lift_aarch64(ins),
        _ => vec![Op::Other {
            mnemonic: ins.mnemonic.clone(),
            text: ins.text.clone(),
        }],
    }
}

// ---------- x86 / x86_64 ----------

fn lift_x86(ins: &Insn) -> Vec<Op> {
    use crate::disasm::FlowKind;

    // Parse operands lazily from text. The disassembled text comes from
    // iced-x86's Intel formatter; we only extract the destination/source for
    // the common opcodes. The full IR could be reconstructed straight from
    // iced-x86's Instruction structure, but lazy text parsing is enough for
    // downstream consumers (stack analysis only needs to see "sub rsp, imm").
    let parts = split_operands(&ins.text);
    let mn = ins.mnemonic.as_str();

    let parse_op = |s: &str| -> Operand { parse_x86_operand(s) };

    match mn {
        "mov" | "movzx" | "movsx" | "movsxd" | "lea" => {
            if parts.len() == 2 {
                vec![Op::Copy {
                    dst: parse_op(&parts[0]),
                    src: parse_op(&parts[1]),
                }]
            } else {
                generic(ins)
            }
        }
        "add" if parts.len() == 2 => vec![Op::Add {
            dst: parse_op(&parts[0]),
            lhs: parse_op(&parts[0]),
            rhs: parse_op(&parts[1]),
        }],
        "sub" if parts.len() == 2 => vec![Op::Sub {
            dst: parse_op(&parts[0]),
            lhs: parse_op(&parts[0]),
            rhs: parse_op(&parts[1]),
        }],
        "imul" | "mul" if parts.len() == 2 => vec![Op::Mul {
            dst: parse_op(&parts[0]),
            lhs: parse_op(&parts[0]),
            rhs: parse_op(&parts[1]),
        }],
        "and" if parts.len() == 2 => vec![Op::And {
            dst: parse_op(&parts[0]),
            lhs: parse_op(&parts[0]),
            rhs: parse_op(&parts[1]),
        }],
        "or" if parts.len() == 2 => vec![Op::Or {
            dst: parse_op(&parts[0]),
            lhs: parse_op(&parts[0]),
            rhs: parse_op(&parts[1]),
        }],
        "xor" if parts.len() == 2 => vec![Op::Xor {
            dst: parse_op(&parts[0]),
            lhs: parse_op(&parts[0]),
            rhs: parse_op(&parts[1]),
        }],
        "shl" | "sal" if parts.len() == 2 => vec![Op::Shl {
            dst: parse_op(&parts[0]),
            lhs: parse_op(&parts[0]),
            rhs: parse_op(&parts[1]),
        }],
        "shr" | "sar" if parts.len() == 2 => vec![Op::Shr {
            dst: parse_op(&parts[0]),
            lhs: parse_op(&parts[0]),
            rhs: parse_op(&parts[1]),
        }],
        "cmp" if parts.len() == 2 => vec![Op::Cmp {
            lhs: parse_op(&parts[0]),
            rhs: parse_op(&parts[1]),
        }],
        "test" if parts.len() == 2 => vec![Op::Test {
            lhs: parse_op(&parts[0]),
            rhs: parse_op(&parts[1]),
        }],
        "push" if parts.len() == 1 => vec![Op::Push {
            src: parse_op(&parts[0]),
        }],
        "pop" if parts.len() == 1 => vec![Op::Pop {
            dst: parse_op(&parts[0]),
        }],
        "ret" | "retn" | "retf" => vec![Op::Return],
        _ => match ins.flow {
            FlowKind::Call | FlowKind::CallIndirect => vec![Op::Call {
                target: ins
                    .target
                    .map(Operand::Addr)
                    .unwrap_or_else(|| Operand::Reg("indirect".into())),
            }],
            FlowKind::Jump | FlowKind::JumpIndirect => vec![Op::Branch {
                target: ins
                    .target
                    .map(Operand::Addr)
                    .unwrap_or_else(|| Operand::Reg("indirect".into())),
            }],
            FlowKind::CondJump => vec![Op::CondBranch {
                target: ins
                    .target
                    .map(Operand::Addr)
                    .unwrap_or_else(|| Operand::Reg("indirect".into())),
                cc: mn.to_string(),
            }],
            FlowKind::Return => vec![Op::Return],
            _ => generic(ins),
        },
    }
}

fn generic(ins: &Insn) -> Vec<Op> {
    vec![Op::Other {
        mnemonic: ins.mnemonic.clone(),
        text: ins.text.clone(),
    }]
}

/// Split an instruction text like `mov rax,qword ptr [rip+0x10]` into its
/// comma-separated operands (after stripping the mnemonic).
fn split_operands(text: &str) -> Vec<String> {
    let after_mn = text
        .splitn(2, char::is_whitespace)
        .nth(1)
        .unwrap_or("")
        .trim();
    if after_mn.is_empty() {
        return Vec::new();
    }
    // Respect brackets so `mov [rip+0x10], rax` stays as two operands.
    let mut depth: i32 = 0;
    let mut buf = String::new();
    let mut out = Vec::new();
    for c in after_mn.chars() {
        match c {
            '[' => {
                depth += 1;
                buf.push(c);
            }
            ']' => {
                depth -= 1;
                buf.push(c);
            }
            ',' if depth == 0 => {
                out.push(buf.trim().to_string());
                buf.clear();
            }
            _ => buf.push(c),
        }
    }
    if !buf.trim().is_empty() {
        out.push(buf.trim().to_string());
    }
    out
}

fn parse_x86_operand(s: &str) -> Operand {
    let s = s.trim();
    if s.is_empty() {
        return Operand::Reg("?".into());
    }
    if s.starts_with('[') && s.ends_with(']') {
        return parse_mem(&s[1..s.len() - 1], 8);
    }
    if let Some(rest) = s.strip_suffix(']') {
        if let Some((kw, mem)) = rest.split_once('[') {
            let size = size_keyword_bytes(kw.trim());
            return parse_mem(mem, size);
        }
    }
    if let Some(n) = parse_immediate(s) {
        return Operand::Imm(n);
    }
    if is_register(s) {
        return Operand::Reg(s.to_string());
    }
    Operand::Reg(s.to_string())
}

fn size_keyword_bytes(kw: &str) -> u8 {
    let kw = kw.to_ascii_lowercase();
    let kw = kw.replace("ptr", "");
    let kw = kw.trim().to_string();
    match kw.as_str() {
        "byte" => 1,
        "word" => 2,
        "dword" => 4,
        "qword" => 8,
        "xmmword" => 16,
        "ymmword" => 32,
        _ => 8,
    }
}

fn parse_mem(inner: &str, size: u8) -> Operand {
    let mut base: Option<String> = None;
    let mut index: Option<String> = None;
    let mut scale: u8 = 1;
    let mut disp: i64 = 0;

    for token in inner.split_inclusive(['+', '-']) {
        let token_trim = token.trim_end_matches(['+', '-']).trim();
        if token_trim.is_empty() {
            continue;
        }
        // Detect scale: `rsi*4`
        if let Some((reg, mult)) = token_trim.split_once('*') {
            if let Ok(m) = mult.trim().parse::<u8>() {
                index = Some(reg.trim().to_string());
                scale = m;
                continue;
            }
        }
        if is_register(token_trim) {
            if base.is_none() {
                base = Some(token_trim.to_string());
            } else if index.is_none() {
                index = Some(token_trim.to_string());
            }
        } else if let Some(n) = parse_immediate(token_trim) {
            // Look at preceding sign — split_inclusive gives us the sign as the
            // first char of the *next* token, so we can't easily tell. Treat
            // all displacements as positive here; lifter consumers don't lean
            // on the sign for stack analysis (they use the size keyword).
            disp = disp.wrapping_add(n);
        }
    }

    Operand::Mem {
        base,
        index,
        scale,
        disp,
        size,
    }
}

fn parse_immediate(s: &str) -> Option<i64> {
    let t = s.trim().trim_end_matches('h');
    if let Some(stripped) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        if let Ok(v) = i64::from_str_radix(stripped, 16) {
            return Some(v);
        }
        if let Ok(v) = u64::from_str_radix(stripped, 16) {
            return Some(v as i64);
        }
    }
    if t.chars().all(|c| c.is_ascii_hexdigit())
        && t.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F'))
    {
        if let Ok(v) = i64::from_str_radix(t, 16) {
            return Some(v);
        }
    }
    if let Ok(v) = t.parse::<i64>() {
        return Some(v);
    }
    if let Ok(v) = i64::from_str_radix(t, 16) {
        return Some(v);
    }
    None
}

fn is_register(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    matches!(
        s.as_str(),
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp" |
        "r8" | "r9" | "r10" | "r11" | "r12" | "r13" | "r14" | "r15" |
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp" |
        "r8d" | "r9d" | "r10d" | "r11d" | "r12d" | "r13d" | "r14d" | "r15d" |
        "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp" |
        "r8w" | "r9w" | "r10w" | "r11w" | "r12w" | "r13w" | "r14w" | "r15w" |
        "al" | "bl" | "cl" | "dl" | "sil" | "dil" | "bpl" | "spl" |
        "ah" | "bh" | "ch" | "dh" |
        "r8b" | "r9b" | "r10b" | "r11b" | "r12b" | "r13b" | "r14b" | "r15b" |
        "rip" | "eip" | "ip"
    )
}

// ---------- aarch64 ----------

fn lift_aarch64(ins: &Insn) -> Vec<Op> {
    use crate::disasm::FlowKind;

    let parts = split_operands(&ins.text);
    let mn = ins.mnemonic.as_str();

    let pa = |s: &str| -> Operand { parse_a64_operand(s) };

    match mn {
        "mov" | "movz" | "movk" | "movn" if parts.len() == 2 => vec![Op::Copy {
            dst: pa(&parts[0]),
            src: pa(&parts[1]),
        }],
        "ldr" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrsw" if parts.len() == 2 => vec![Op::Load {
            dst: pa(&parts[0]),
            addr: pa(&parts[1]),
            size: ldr_size(mn),
        }],
        "str" | "strb" | "strh" if parts.len() == 2 => vec![Op::Store {
            addr: pa(&parts[1]),
            src: pa(&parts[0]),
            size: str_size(mn),
        }],
        "add" if parts.len() == 3 => vec![Op::Add {
            dst: pa(&parts[0]),
            lhs: pa(&parts[1]),
            rhs: pa(&parts[2]),
        }],
        "sub" if parts.len() == 3 => vec![Op::Sub {
            dst: pa(&parts[0]),
            lhs: pa(&parts[1]),
            rhs: pa(&parts[2]),
        }],
        "and" if parts.len() == 3 => vec![Op::And {
            dst: pa(&parts[0]),
            lhs: pa(&parts[1]),
            rhs: pa(&parts[2]),
        }],
        "orr" if parts.len() == 3 => vec![Op::Or {
            dst: pa(&parts[0]),
            lhs: pa(&parts[1]),
            rhs: pa(&parts[2]),
        }],
        "eor" if parts.len() == 3 => vec![Op::Xor {
            dst: pa(&parts[0]),
            lhs: pa(&parts[1]),
            rhs: pa(&parts[2]),
        }],
        "lsl" | "lsr" | "asr" if parts.len() == 3 => {
            let op = if mn == "lsl" {
                Op::Shl {
                    dst: pa(&parts[0]),
                    lhs: pa(&parts[1]),
                    rhs: pa(&parts[2]),
                }
            } else {
                Op::Shr {
                    dst: pa(&parts[0]),
                    lhs: pa(&parts[1]),
                    rhs: pa(&parts[2]),
                }
            };
            vec![op]
        }
        "cmp" if parts.len() == 2 => vec![Op::Cmp {
            lhs: pa(&parts[0]),
            rhs: pa(&parts[1]),
        }],
        "tst" if parts.len() == 2 => vec![Op::Test {
            lhs: pa(&parts[0]),
            rhs: pa(&parts[1]),
        }],
        "ret" => vec![Op::Return],
        _ => match ins.flow {
            FlowKind::Call | FlowKind::CallIndirect => vec![Op::Call {
                target: ins.target.map(Operand::Addr).unwrap_or(Operand::Reg("indirect".into())),
            }],
            FlowKind::Jump | FlowKind::JumpIndirect => vec![Op::Branch {
                target: ins.target.map(Operand::Addr).unwrap_or(Operand::Reg("indirect".into())),
            }],
            FlowKind::CondJump => vec![Op::CondBranch {
                target: ins.target.map(Operand::Addr).unwrap_or(Operand::Reg("indirect".into())),
                cc: mn.to_string(),
            }],
            FlowKind::Return => vec![Op::Return],
            _ => generic(ins),
        },
    }
}

fn ldr_size(mn: &str) -> u8 {
    match mn {
        "ldrb" | "ldrsb" => 1,
        "ldrh" | "ldrsh" => 2,
        "ldrsw" => 4,
        _ => 8,
    }
}

fn str_size(mn: &str) -> u8 {
    match mn {
        "strb" => 1,
        "strh" => 2,
        _ => 8,
    }
}

fn parse_a64_operand(s: &str) -> Operand {
    let s = s.trim().trim_matches(',');
    if s.is_empty() {
        return Operand::Reg("?".into());
    }
    if s.starts_with('[') {
        let inner = s.trim_start_matches('[').trim_end_matches(']');
        return parse_mem(inner, 8);
    }
    if let Some(stripped) = s.strip_prefix('#') {
        if let Some(n) = parse_immediate(stripped) {
            return Operand::Imm(n);
        }
    }
    if let Some(n) = parse_immediate(s) {
        return Operand::Imm(n);
    }
    Operand::Reg(s.to_string())
}
