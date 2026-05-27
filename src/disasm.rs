//! Multi-arch disassembler. x86_64 via `iced-x86`, ARM64 via `yaxpeax-arm`.
//!
//! Returns a uniform `Insn` record (address, raw bytes, mnemonic, full text,
//! plus optional control-flow info) so downstream modules (xrefs, CFG)
//! can stay arch-agnostic.

use crate::loader::{Arch, Binary};
use anyhow::{anyhow, Result};
use serde::Serialize;

/// Kind of control flow effect, used by the xref + CFG builders.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum FlowKind {
    /// Falls through to the next instruction.
    Sequential,
    /// Unconditional jump.
    Jump,
    /// Conditional jump (both branch and fall-through reachable).
    CondJump,
    /// Direct call (and fall-through).
    Call,
    /// Indirect jump (target unknown).
    JumpIndirect,
    /// Indirect call (target unknown, returns).
    CallIndirect,
    /// Return / end of function.
    Return,
    /// Interrupt / undefined / halt — treated as non-fallthrough end.
    EndBlock,
}

impl FlowKind {
    #[allow(dead_code)]
    pub fn falls_through(self) -> bool {
        matches!(
            self,
            FlowKind::Sequential | FlowKind::CondJump | FlowKind::Call | FlowKind::CallIndirect
        )
    }

    #[allow(dead_code)]
    pub fn ends_block(self) -> bool {
        !matches!(self, FlowKind::Sequential)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Insn {
    pub address: u64,
    pub size: usize,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub text: String,
    pub flow: FlowKind,
    /// Direct branch/call destination, when statically known.
    pub target: Option<u64>,
}

/// Disassemble a slice of code at `base_addr`.
pub fn disassemble(arch: Arch, base_addr: u64, bytes: &[u8]) -> Result<Vec<Insn>> {
    match arch {
        Arch::X86_64 => Ok(disasm_x86(64, base_addr, bytes)),
        Arch::X86 => Ok(disasm_x86(32, base_addr, bytes)),
        Arch::Aarch64 => Ok(disasm_aarch64(base_addr, bytes)),
        other => Err(anyhow!(
            "disassembly for {} not implemented; only x86/x86_64/aarch64 are wired up",
            other.as_str()
        )),
    }
}

/// Convenience: disassemble a range from the binary by virtual address.
pub fn disassemble_va(bin: &Binary, vaddr: u64, len: usize) -> Result<Vec<Insn>> {
    let slice = bin
        .read_va(vaddr, len)
        .ok_or_else(|| anyhow!("vaddr {:#x} not mapped", vaddr))?;
    disassemble(bin.arch, vaddr, slice)
}

// ---------- x86 / x86_64 ----------

fn disasm_x86(bitness: u32, base_addr: u64, bytes: &[u8]) -> Vec<Insn> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, OpKind};

    let mut decoder = Decoder::with_ip(bitness, bytes, base_addr, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_first_operand_char_index(8);
    let mut text_buf = String::new();

    let mut out = Vec::new();
    while decoder.can_decode() {
        let insn = decoder.decode();
        text_buf.clear();
        formatter.format(&insn, &mut text_buf);

        let start = (insn.ip() - base_addr) as usize;
        let end = start + insn.len();
        let raw = bytes
            .get(start..end)
            .map(|s| s.to_vec())
            .unwrap_or_default();

        let mnemonic = format!("{:?}", insn.mnemonic()).to_lowercase();

        let (flow, target) = match insn.flow_control() {
            FlowControl::Next => (FlowKind::Sequential, None),
            FlowControl::Return => (FlowKind::Return, None),
            FlowControl::UnconditionalBranch => {
                let t = if insn.op_count() > 0 && matches!(insn.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                    Some(insn.near_branch_target())
                } else {
                    None
                };
                (FlowKind::Jump, t)
            }
            FlowControl::ConditionalBranch => {
                let t = if insn.op_count() > 0 && matches!(insn.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                    Some(insn.near_branch_target())
                } else {
                    None
                };
                (FlowKind::CondJump, t)
            }
            FlowControl::Call => {
                let t = if insn.op_count() > 0 && matches!(insn.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                    Some(insn.near_branch_target())
                } else {
                    None
                };
                (FlowKind::Call, t)
            }
            FlowControl::IndirectBranch => (FlowKind::JumpIndirect, None),
            FlowControl::IndirectCall => (FlowKind::CallIndirect, None),
            FlowControl::Interrupt | FlowControl::Exception => (FlowKind::EndBlock, None),
            FlowControl::XbeginXabortXend => (FlowKind::Sequential, None),
        };

        out.push(Insn {
            address: insn.ip(),
            size: insn.len(),
            bytes: raw,
            mnemonic,
            text: text_buf.clone(),
            flow,
            target,
        });
    }
    out
}

// ---------- aarch64 ----------

fn disasm_aarch64(base_addr: u64, bytes: &[u8]) -> Vec<Insn> {
    use yaxpeax_arch::Decoder;
    use yaxpeax_arm::armv8::a64::{ARMv8, Opcode};

    let decoder = <ARMv8 as yaxpeax_arch::Arch>::Decoder::default();
    let mut out = Vec::new();
    let mut i: usize = 0;
    while i + 4 <= bytes.len() {
        let chunk: [u8; 4] = bytes[i..i + 4].try_into().unwrap();
        let word = u32::from_le_bytes(chunk);
        let mut reader =
            yaxpeax_arch::U8Reader::new(&bytes[i..i + 4]);
        let insn_addr = base_addr + i as u64;
        let (mnemonic, text, flow, target) = match decoder.decode(&mut reader) {
            Ok(insn) => {
                let op = insn.opcode;
                let mn = format!("{:?}", op).to_lowercase();
                let text = format!("{}", insn);

                let (flow, target) = match op {
                    Opcode::B => (
                        FlowKind::Jump,
                        branch_target_a64(&insn.operands, insn_addr),
                    ),
                    Opcode::BL => (
                        FlowKind::Call,
                        branch_target_a64(&insn.operands, insn_addr),
                    ),
                    Opcode::BR => (FlowKind::JumpIndirect, None),
                    Opcode::BLR => (FlowKind::CallIndirect, None),
                    Opcode::RET | Opcode::ERET => (FlowKind::Return, None),
                    Opcode::Bcc(_)
                    | Opcode::CBZ
                    | Opcode::CBNZ
                    | Opcode::TBZ
                    | Opcode::TBNZ => (
                        FlowKind::CondJump,
                        branch_target_a64(&insn.operands, insn_addr),
                    ),
                    Opcode::HLT | Opcode::BRK | Opcode::HVC | Opcode::SMC | Opcode::SVC => {
                        (FlowKind::EndBlock, None)
                    }
                    _ => (FlowKind::Sequential, None),
                };

                (mn, text, flow, target)
            }
            Err(_) => (
                "<bad>".to_string(),
                format!(".word {:#010x}", word),
                FlowKind::Sequential,
                None,
            ),
        };

        out.push(Insn {
            address: insn_addr,
            size: 4,
            bytes: bytes[i..i + 4].to_vec(),
            mnemonic,
            text,
            flow,
            target,
        });

        i += 4;
    }
    out
}

fn branch_target_a64(
    operands: &[yaxpeax_arm::armv8::a64::Operand; 4],
    insn_addr: u64,
) -> Option<u64> {
    use yaxpeax_arm::armv8::a64::Operand;
    for op in operands {
        if let Operand::PCOffset(off) = op {
            return Some((insn_addr as i64).wrapping_add(*off as i64) as u64);
        }
    }
    None
}
