//! Per-function control flow graph and project-wide call graph.
//!
//! Both come out as `petgraph::Graph<...>` so callers can do dominators,
//! reachability, etc. Both can emit Graphviz DOT for visualization.

use crate::disasm::{FlowKind, Insn};
use crate::functions::Function;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

// ---------- CFG ----------

#[derive(Debug, Clone, Serialize)]
pub struct BasicBlock {
    pub start: u64,
    pub end: u64,
    pub instructions: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cfg {
    pub function: u64,
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<(u64, u64, EdgeKind)>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EdgeKind {
    Fall,
    Jump,
    Branch,
}

pub fn build_cfg(function_entry: u64, insns: &[Insn]) -> Cfg {
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    if let Some(first) = insns.first() {
        leaders.insert(first.address);
    }

    let addrs: BTreeSet<u64> = insns.iter().map(|i| i.address).collect();
    for (i, ins) in insns.iter().enumerate() {
        let next_addr = ins.address + ins.size as u64;
        match ins.flow {
            FlowKind::Jump | FlowKind::CondJump => {
                if let Some(t) = ins.target {
                    if addrs.contains(&t) {
                        leaders.insert(t);
                    }
                }
                if matches!(ins.flow, FlowKind::CondJump) && i + 1 < insns.len() {
                    leaders.insert(next_addr);
                }
                if matches!(ins.flow, FlowKind::Jump) && i + 1 < insns.len() {
                    leaders.insert(next_addr);
                }
            }
            FlowKind::Return | FlowKind::EndBlock | FlowKind::JumpIndirect => {
                if i + 1 < insns.len() {
                    leaders.insert(next_addr);
                }
            }
            _ => {}
        }
    }

    let leader_vec: Vec<u64> = leaders.into_iter().collect();
    let leader_idx: HashMap<u64, usize> = leader_vec
        .iter()
        .enumerate()
        .map(|(i, &a)| (a, i))
        .collect();

    let mut blocks: Vec<BasicBlock> = leader_vec
        .iter()
        .map(|&start| BasicBlock {
            start,
            end: start,
            instructions: Vec::new(),
        })
        .collect();

    let mut current_block_idx: Option<usize> = None;
    let mut last_ins: Option<&Insn> = None;
    let mut edges: Vec<(u64, u64, EdgeKind)> = Vec::new();

    for ins in insns {
        if let Some(&bi) = leader_idx.get(&ins.address) {
            // close previous block if it fell through
            if let (Some(pi), Some(li)) = (current_block_idx, last_ins) {
                if matches!(li.flow, FlowKind::Sequential | FlowKind::Call | FlowKind::CallIndirect) {
                    let from = leader_vec[pi];
                    let to = ins.address;
                    edges.push((from, to, EdgeKind::Fall));
                }
            }
            current_block_idx = Some(bi);
        }
        if let Some(bi) = current_block_idx {
            blocks[bi].instructions.push(ins.address);
            blocks[bi].end = ins.address + ins.size as u64;
        }
        match ins.flow {
            FlowKind::Jump => {
                if let (Some(bi), Some(t)) = (current_block_idx, ins.target) {
                    if leader_idx.contains_key(&t) {
                        edges.push((leader_vec[bi], t, EdgeKind::Jump));
                    }
                }
            }
            FlowKind::CondJump => {
                if let (Some(bi), Some(t)) = (current_block_idx, ins.target) {
                    if leader_idx.contains_key(&t) {
                        edges.push((leader_vec[bi], t, EdgeKind::Branch));
                    }
                }
            }
            _ => {}
        }
        last_ins = Some(ins);
    }

    // de-dup edges
    let mut set: BTreeSet<(u64, u64, EdgeKind)> = BTreeSet::new();
    for e in edges {
        set.insert(e);
    }

    Cfg {
        function: function_entry,
        blocks,
        edges: set.into_iter().collect(),
    }
}

impl Cfg {
    pub fn to_dot(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "digraph cfg_{:x} {{", self.function);
        let _ = writeln!(out, "  node [shape=box, fontname=monospace];");
        for b in &self.blocks {
            let _ = writeln!(
                out,
                "  \"{:#x}\" [label=\"{:#x} .. {:#x}\\n({} insns)\"];",
                b.start,
                b.start,
                b.end,
                b.instructions.len()
            );
        }
        for (from, to, kind) in &self.edges {
            let style = match kind {
                EdgeKind::Fall => "style=dashed",
                EdgeKind::Jump => "color=blue",
                EdgeKind::Branch => "color=red",
            };
            let _ = writeln!(out, "  \"{:#x}\" -> \"{:#x}\" [{}];", from, to, style);
        }
        let _ = writeln!(out, "}}");
        out
    }
}

// ---------- Call graph ----------

#[derive(Debug, Clone, Serialize)]
pub struct CallGraphNode {
    pub name: String,
    pub entry: u64,
}

pub struct CallGraph {
    pub graph: DiGraph<CallGraphNode, ()>,
    #[allow(dead_code)]
    pub by_entry: BTreeMap<u64, NodeIndex>,
}

pub fn build_call_graph(functions: &[Function]) -> CallGraph {
    let mut graph: DiGraph<CallGraphNode, ()> = DiGraph::new();
    let mut by_entry: BTreeMap<u64, NodeIndex> = BTreeMap::new();
    for f in functions {
        let idx = graph.add_node(CallGraphNode {
            name: f.name.clone(),
            entry: f.entry,
        });
        by_entry.insert(f.entry, idx);
    }
    for f in functions {
        let src = by_entry[&f.entry];
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        for &target in &f.calls {
            if !seen.insert(target) {
                continue;
            }
            if let Some(&dst) = by_entry.get(&target) {
                graph.add_edge(src, dst, ());
            }
        }
    }
    CallGraph { graph, by_entry }
}

impl CallGraph {
    pub fn to_dot(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "digraph callgraph {{");
        let _ = writeln!(out, "  rankdir=LR;");
        let _ = writeln!(out, "  node [shape=oval, fontname=monospace];");
        for node in self.graph.node_weights() {
            let _ = writeln!(
                out,
                "  \"{:#x}\" [label=\"{}\\n{:#x}\"];",
                node.entry, node.name, node.entry
            );
        }
        for edge in self.graph.edge_indices() {
            let (a, b) = self.graph.edge_endpoints(edge).unwrap();
            let from = self.graph[a].entry;
            let to = self.graph[b].entry;
            let _ = writeln!(out, "  \"{:#x}\" -> \"{:#x}\";", from, to);
        }
        let _ = writeln!(out, "}}");
        out
    }

    pub fn to_json(&self) -> serde_json::Value {
        let nodes: Vec<_> = self
            .graph
            .node_weights()
            .map(|n| serde_json::json!({"name": n.name, "entry": n.entry}))
            .collect();
        let edges: Vec<_> = self
            .graph
            .edge_indices()
            .map(|e| {
                let (a, b) = self.graph.edge_endpoints(e).unwrap();
                serde_json::json!({
                    "from": self.graph[a].entry,
                    "to": self.graph[b].entry,
                })
            })
            .collect();
        serde_json::json!({"nodes": nodes, "edges": edges})
    }
}
