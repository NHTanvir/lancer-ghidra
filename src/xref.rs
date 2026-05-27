//! Cross-reference index built from disassembled functions.
//!
//! For each direct call/jump we record an edge `from → to`. Look-up is
//! bidirectional: "what calls X?" and "what does X call?".

use crate::disasm::{FlowKind, Insn};
use crate::functions::Function;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum XrefKind {
    Call,
    Jump,
    CondJump,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
}

#[derive(Default, Debug, Serialize)]
pub struct XrefIndex {
    pub edges: BTreeSet<Xref>,
    /// to → set(from)
    pub to_from: BTreeMap<u64, BTreeSet<u64>>,
    /// from → set(to)
    pub from_to: BTreeMap<u64, BTreeSet<u64>>,
}

impl XrefIndex {
    pub fn add(&mut self, x: Xref) {
        self.to_from.entry(x.to).or_default().insert(x.from);
        self.from_to.entry(x.from).or_default().insert(x.to);
        self.edges.insert(x);
    }

    pub fn references_to(&self, vaddr: u64) -> Vec<u64> {
        self.to_from
            .get(&vaddr)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn references_from(&self, vaddr: u64) -> Vec<u64> {
        self.from_to
            .get(&vaddr)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }
}

pub fn build_for_function(idx: &mut XrefIndex, _entry: u64, insns: &[Insn]) {
    for ins in insns {
        let kind = match ins.flow {
            FlowKind::Call => XrefKind::Call,
            FlowKind::Jump => XrefKind::Jump,
            FlowKind::CondJump => XrefKind::CondJump,
            _ => continue,
        };
        if let Some(t) = ins.target {
            idx.add(Xref {
                from: ins.address,
                to: t,
                kind,
            });
        }
    }
}

/// Build a single index across every function's disassembly.
pub fn build_index<'a, I>(per_function: I) -> XrefIndex
where
    I: IntoIterator<Item = (&'a Function, &'a [Insn])>,
{
    let mut idx = XrefIndex::default();
    for (f, insns) in per_function {
        build_for_function(&mut idx, f.entry, insns);
    }
    idx
}
