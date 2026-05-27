//! AI decompiler stub (phase 3 of plan.md).
//!
//! Strategy: assemble a *prompt blob* with the target function's disassembly,
//! incoming/outgoing xrefs, nearby strings, and signature hints. Write the
//! blob to stdout (or `--out FILE`) so the user can pipe it into any chat
//! model. A `--send` mode (Anthropic / OpenAI) is left as a future hook —
//! sending API requests is intentionally out of scope for the offline CLI.
//!
//! This matches the recommendation in plan.md: "the most promising path is
//! LLM-based decompilation … feed disassembly to a code-trained model".

use crate::disasm::Insn;
use crate::functions::Function;
use crate::loader::Binary;
use crate::strings::FoundString;
use crate::xref::XrefIndex;
use std::fmt::Write as _;

pub struct DecompileContext<'a> {
    pub bin: &'a Binary,
    pub func: &'a Function,
    pub insns: &'a [Insn],
    pub xrefs: &'a XrefIndex,
    pub all_strings: &'a [FoundString],
    pub all_functions: &'a [Function],
}

pub fn build_prompt(ctx: &DecompileContext<'_>) -> String {
    let mut out = String::new();
    let bin = ctx.bin;
    let f = ctx.func;

    let _ = writeln!(out, "You are a senior reverse engineer. The user has supplied a disassembled function from a {} binary on {}.", binary_format_str(bin), bin.arch.as_str());
    let _ = writeln!(out, "Recover idiomatic, readable C-like pseudocode for it.\n");
    let _ = writeln!(out, "Rules:");
    let _ = writeln!(out, "  - keep behavior identical");
    let _ = writeln!(out, "  - name parameters and locals plausibly");
    let _ = writeln!(out, "  - recognize standard library / OS API calls when you can");
    let _ = writeln!(out, "  - flag any obvious memory-safety / integer / format-string bugs at the bottom\n");

    let _ = writeln!(out, "## Function");
    let _ = writeln!(out, "Name      : {}", f.name);
    let _ = writeln!(out, "Entry     : {:#x}", f.entry);
    let _ = writeln!(out, "Size      : {} bytes", f.size);
    let _ = writeln!(out, "Source    : {:?}\n", f.source);

    let mut callers: Vec<u64> = ctx
        .xrefs
        .references_to(f.entry)
        .into_iter()
        .collect();
    callers.sort();
    callers.dedup();
    if !callers.is_empty() {
        let _ = writeln!(out, "## Callers ({}):", callers.len());
        for c in callers.iter().take(16) {
            let name = ctx
                .all_functions
                .iter()
                .find(|other| {
                    *c >= other.entry && *c < other.end
                })
                .map(|x| x.name.as_str())
                .unwrap_or("?");
            let _ = writeln!(out, "  {:#x}  in  {}", c, name);
        }
        out.push('\n');
    }

    if !f.calls.is_empty() {
        let _ = writeln!(out, "## Direct calls ({}):", f.calls.len());
        let mut seen = std::collections::HashSet::new();
        for &t in &f.calls {
            if !seen.insert(t) {
                continue;
            }
            let name = ctx
                .all_functions
                .iter()
                .find(|x| x.entry == t)
                .map(|x| x.name.as_str())
                .unwrap_or("?");
            let _ = writeln!(out, "  -> {:#x}  {}", t, name);
        }
        out.push('\n');
    }

    let nearby: Vec<&FoundString> = ctx
        .all_strings
        .iter()
        .filter(|s| ctx.xrefs.references_to(s.vaddr).iter().any(|from| *from >= f.entry && *from < f.end))
        .collect();
    if !nearby.is_empty() {
        let _ = writeln!(out, "## Strings referenced in this function:");
        for s in nearby.iter().take(16) {
            let _ = writeln!(out, "  {:#x}  {:?}", s.vaddr, s.value);
        }
        out.push('\n');
    }

    let _ = writeln!(out, "## Disassembly\n```");
    for ins in ctx.insns {
        let bytes_hex: String = ins
            .bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(out, "{:#010x}: {:<24} {}", ins.address, bytes_hex, ins.text);
    }
    let _ = writeln!(out, "```\n");

    let _ = writeln!(out, "## Output format");
    let _ = writeln!(out, "Reply with:");
    let _ = writeln!(out, "  1. a C-style function definition (pseudocode is fine)");
    let _ = writeln!(out, "  2. 1-3 lines explaining what the function does");
    let _ = writeln!(out, "  3. any suspected bugs, or `no obvious bugs`");

    out
}

fn binary_format_str(bin: &Binary) -> &'static str {
    match bin.format {
        crate::loader::Format::Elf => "Linux ELF",
        crate::loader::Format::Pe => "Windows PE",
        crate::loader::Format::MachO => "Mach-O",
        crate::loader::Format::Archive => "archive",
        crate::loader::Format::Unknown => "binary",
    }
}
