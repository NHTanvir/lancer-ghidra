//! Rhai scripting host.
//!
//! Exposes a small reverse-engineering API to user scripts so they can
//! enumerate functions, read disassembly, rename, comment, and extract
//! strings — same surface as GhidraScript on a much smaller budget.
//!
//! Script entry point: a file with a `main()` function, or top-level
//! statements. The script has `bin` (the binary's metadata) and `ctx` (the
//! script API) in scope.

use anyhow::{Context, Result};
use rhai::{Dynamic, Engine, Scope, AST};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::db::ProjectDb;
use crate::disasm::{disassemble_va, Insn};
use crate::functions::{analyze, AnalysisOptions, Function};
use crate::loader::Binary;
use crate::strings::{extract, FoundString};

/// Public to scripts as `ctx`.
#[derive(Clone)]
pub struct ScriptApi {
    inner: Arc<Mutex<ScriptInner>>,
}

struct ScriptInner {
    bin: Binary,
    functions: Vec<Function>,
    strings: Vec<FoundString>,
    db: Option<ProjectDb>,
}

impl ScriptApi {
    pub fn list_functions(&mut self) -> Vec<Dynamic> {
        let g = self.inner.lock().unwrap();
        g.functions
            .iter()
            .map(|f| {
                let mut m = rhai::Map::new();
                m.insert("name".into(), Dynamic::from(f.name.clone()));
                m.insert("entry".into(), Dynamic::from(f.entry as i64));
                m.insert("size".into(), Dynamic::from(f.size as i64));
                Dynamic::from_map(m)
            })
            .collect()
    }

    pub fn disasm(&mut self, addr: i64, length: i64) -> Vec<Dynamic> {
        let g = self.inner.lock().unwrap();
        let insns = disassemble_va(&g.bin, addr as u64, length as usize).unwrap_or_default();
        insns.into_iter().map(insn_to_dynamic).collect()
    }

    pub fn function_disasm(&mut self, addr: i64) -> Vec<Dynamic> {
        let g = self.inner.lock().unwrap();
        let Some(f) = g.functions.iter().find(|f| f.entry == addr as u64) else {
            return Vec::new();
        };
        let Some(bytes) = g.bin.read_va(f.entry, f.size as usize) else {
            return Vec::new();
        };
        let Ok(insns) = crate::disasm::disassemble(g.bin.arch, f.entry, bytes) else {
            return Vec::new();
        };
        insns.into_iter().map(insn_to_dynamic).collect()
    }

    pub fn list_strings(&mut self) -> Vec<Dynamic> {
        let g = self.inner.lock().unwrap();
        g.strings
            .iter()
            .map(|s| {
                let mut m = rhai::Map::new();
                m.insert("vaddr".into(), Dynamic::from(s.vaddr as i64));
                m.insert("value".into(), Dynamic::from(s.value.clone()));
                Dynamic::from_map(m)
            })
            .collect()
    }

    pub fn rename(&mut self, addr: i64, name: &str) -> bool {
        let g = self.inner.lock().unwrap();
        if let Some(db) = &g.db {
            db.set_rename(addr as u64, name).is_ok()
        } else {
            false
        }
    }

    pub fn comment(&mut self, addr: i64, text: &str) -> bool {
        let g = self.inner.lock().unwrap();
        if let Some(db) = &g.db {
            db.set_comment(addr as u64, text).is_ok()
        } else {
            false
        }
    }

    pub fn arch(&mut self) -> String {
        self.inner.lock().unwrap().bin.arch.as_str().to_string()
    }

    pub fn entry(&mut self) -> i64 {
        self.inner.lock().unwrap().bin.entry as i64
    }
}

fn insn_to_dynamic(i: Insn) -> Dynamic {
    let mut m = rhai::Map::new();
    m.insert("address".into(), Dynamic::from(i.address as i64));
    m.insert("text".into(), Dynamic::from(i.text));
    m.insert("mnemonic".into(), Dynamic::from(i.mnemonic));
    m.insert("size".into(), Dynamic::from(i.size as i64));
    Dynamic::from_map(m)
}

/// Run a `.rhai` file against a loaded binary, with an optional project DB
/// for `ctx.rename` / `ctx.comment` persistence.
pub fn run_script(script_path: &Path, bin: Binary, db: Option<ProjectDb>) -> Result<()> {
    let funcs = analyze(&bin, &AnalysisOptions::default());
    let strs = extract(&bin, crate::strings::DEFAULT_MIN_LEN);

    let api = ScriptApi {
        inner: Arc::new(Mutex::new(ScriptInner {
            bin,
            functions: funcs,
            strings: strs,
            db,
        })),
    };

    let mut engine = Engine::new();
    engine.register_type::<ScriptApi>();
    engine.register_fn("list_functions", ScriptApi::list_functions);
    engine.register_fn("disasm", ScriptApi::disasm);
    engine.register_fn("function_disasm", ScriptApi::function_disasm);
    engine.register_fn("list_strings", ScriptApi::list_strings);
    engine.register_fn("rename", ScriptApi::rename);
    engine.register_fn("comment", ScriptApi::comment);
    engine.register_fn("arch", ScriptApi::arch);
    engine.register_fn("entry", ScriptApi::entry);

    let src = std::fs::read_to_string(script_path)
        .with_context(|| format!("failed to read script {}", script_path.display()))?;

    let ast: AST = engine
        .compile(&src)
        .with_context(|| format!("rhai compile error in {}", script_path.display()))?;

    let mut scope = Scope::new();
    scope.push("ctx", api);

    engine
        .run_ast_with_scope(&mut scope, &ast)
        .with_context(|| format!("rhai runtime error in {}", script_path.display()))?;
    Ok(())
}
