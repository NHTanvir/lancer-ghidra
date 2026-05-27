//! Persistent project database — annotations that survive across runs.
//!
//! Backed by `redb`. Keyed by SHA-256 of the binary so a single DB file can
//! hold annotations for many binaries. Stores: renames (addr → name),
//! comments (addr → text), type assignments (addr → type name), data type
//! definitions (name → JSON blob), equates (addr → name).

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const RENAMES: TableDefinition<&str, &str> = TableDefinition::new("renames");
const COMMENTS: TableDefinition<&str, &str> = TableDefinition::new("comments");
const TYPES: TableDefinition<&str, &str> = TableDefinition::new("type_assignments");
const TYPEDEFS: TableDefinition<&str, &str> = TableDefinition::new("type_definitions");
const EQUATES: TableDefinition<&str, &str> = TableDefinition::new("equates");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDef {
    pub name: String,
    pub kind: TypeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeKind {
    Int { size: u8, signed: bool },
    Float { size: u8 },
    Pointer { target: String },
    Struct { fields: Vec<StructField> },
    Enum { values: Vec<(String, i64)> },
    Typedef { aliases: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub offset: u32,
    pub type_name: String,
}

/// A snapshot of every annotation for a given binary — what consumers actually
/// read. Cheap to assemble from the live DB.
#[derive(Debug, Default, Clone, Serialize)]
pub struct AnnotationSet {
    pub renames: BTreeMap<u64, String>,
    pub comments: BTreeMap<u64, String>,
    pub type_assignments: BTreeMap<u64, String>,
    pub type_definitions: BTreeMap<String, TypeDef>,
    pub equates: BTreeMap<u64, String>,
}

pub struct ProjectDb {
    db: Database,
    binary_id: String,
}

impl ProjectDb {
    /// Open (or create) the project DB next to the binary, identified by the
    /// binary's content hash.
    pub fn open(binary_path: &Path, binary_bytes: &[u8]) -> Result<Self> {
        let db_path = default_db_path(binary_path);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let db = Database::create(&db_path)
            .with_context(|| format!("failed to open project DB at {}", db_path.display()))?;

        // Initialize tables on first use so reads don't blow up.
        let init = db.begin_write()?;
        let _ = init.open_table(RENAMES)?;
        let _ = init.open_table(COMMENTS)?;
        let _ = init.open_table(TYPES)?;
        let _ = init.open_table(TYPEDEFS)?;
        let _ = init.open_table(EQUATES)?;
        init.commit()?;

        let mut hasher = Sha256::new();
        hasher.update(binary_bytes);
        let binary_id = hex::encode(hasher.finalize());

        Ok(Self { db, binary_id })
    }

    pub fn binary_id(&self) -> &str {
        &self.binary_id
    }

    fn key(&self, addr: u64) -> String {
        format!("{}:{:x}", self.binary_id, addr)
    }

    fn def_key(&self, name: &str) -> String {
        format!("{}:{}", self.binary_id, name)
    }

    pub fn set_rename(&self, addr: u64, name: &str) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(RENAMES)?;
            t.insert(self.key(addr).as_str(), name)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn clear_rename(&self, addr: u64) -> Result<bool> {
        let tx = self.db.begin_write()?;
        let removed;
        {
            let mut t = tx.open_table(RENAMES)?;
            removed = t.remove(self.key(addr).as_str())?.is_some();
        }
        tx.commit()?;
        Ok(removed)
    }

    pub fn set_comment(&self, addr: u64, text: &str) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(COMMENTS)?;
            t.insert(self.key(addr).as_str(), text)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn clear_comment(&self, addr: u64) -> Result<bool> {
        let tx = self.db.begin_write()?;
        let removed;
        {
            let mut t = tx.open_table(COMMENTS)?;
            removed = t.remove(self.key(addr).as_str())?.is_some();
        }
        tx.commit()?;
        Ok(removed)
    }

    pub fn set_type_assignment(&self, addr: u64, type_name: &str) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(TYPES)?;
            t.insert(self.key(addr).as_str(), type_name)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn add_type_definition(&self, def: &TypeDef) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(TYPEDEFS)?;
            let json = serde_json::to_string(def)?;
            t.insert(self.def_key(&def.name).as_str(), json.as_str())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_equate(&self, addr: u64, name: &str) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(EQUATES)?;
            t.insert(self.key(addr).as_str(), name)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Snapshot every annotation for this binary into an `AnnotationSet`.
    pub fn snapshot(&self) -> Result<AnnotationSet> {
        let tx = self.db.begin_read()?;
        let prefix = format!("{}:", self.binary_id);

        let mut snap = AnnotationSet::default();

        {
            let t = tx.open_table(RENAMES)?;
            for row in t.iter()? {
                let (k, v) = row?;
                let key = k.value();
                if let Some(rest) = key.strip_prefix(&prefix) {
                    if let Ok(addr) = u64::from_str_radix(rest, 16) {
                        snap.renames.insert(addr, v.value().to_string());
                    }
                }
            }
        }
        {
            let t = tx.open_table(COMMENTS)?;
            for row in t.iter()? {
                let (k, v) = row?;
                let key = k.value();
                if let Some(rest) = key.strip_prefix(&prefix) {
                    if let Ok(addr) = u64::from_str_radix(rest, 16) {
                        snap.comments.insert(addr, v.value().to_string());
                    }
                }
            }
        }
        {
            let t = tx.open_table(TYPES)?;
            for row in t.iter()? {
                let (k, v) = row?;
                let key = k.value();
                if let Some(rest) = key.strip_prefix(&prefix) {
                    if let Ok(addr) = u64::from_str_radix(rest, 16) {
                        snap.type_assignments.insert(addr, v.value().to_string());
                    }
                }
            }
        }
        {
            let t = tx.open_table(TYPEDEFS)?;
            for row in t.iter()? {
                let (k, v) = row?;
                let key = k.value();
                if let Some(name) = key.strip_prefix(&prefix) {
                    if let Ok(def) = serde_json::from_str::<TypeDef>(v.value()) {
                        snap.type_definitions.insert(name.to_string(), def);
                    }
                }
            }
        }
        {
            let t = tx.open_table(EQUATES)?;
            for row in t.iter()? {
                let (k, v) = row?;
                let key = k.value();
                if let Some(rest) = key.strip_prefix(&prefix) {
                    if let Ok(addr) = u64::from_str_radix(rest, 16) {
                        snap.equates.insert(addr, v.value().to_string());
                    }
                }
            }
        }

        Ok(snap)
    }
}

/// Default DB location: `<binary>.lancer-ghidra.redb` next to the binary.
fn default_db_path(binary_path: &Path) -> PathBuf {
    let mut p = binary_path.to_path_buf();
    let stem = p.file_name().map(|s| s.to_owned()).unwrap_or_default();
    let new = format!("{}.lancer-ghidra.redb", stem.to_string_lossy());
    p.set_file_name(new);
    p
}
