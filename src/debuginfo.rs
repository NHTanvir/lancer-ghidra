//! Debug info loaders: DWARF (ELF/Mach-O) via `gimli`, PDB via `pdb`.
//!
//! These supplement the symbol table with function names that the static
//! symbol pass may miss (especially for inlined / private functions).

use crate::loader::{Binary, Format, RawSymbol, SymbolKind};
use anyhow::Result;

/// Pull function names + addresses from DWARF `.debug_info`. No-op on PE.
pub fn load_dwarf_symbols(bin: &Binary) -> Result<Vec<RawSymbol>> {
    if bin.format != Format::Elf && bin.format != Format::MachO {
        return Ok(Vec::new());
    }

    let bytes = &bin.bytes[..];
    let object = match object_for_dwarf(bytes) {
        Some(o) => o,
        None => return Ok(Vec::new()),
    };

    let endian = if matches!(bin.endian, crate::loader::Endian::Little) {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> std::result::Result<gimli::EndianSlice<'_, gimli::RunTimeEndian>, gimli::Error> {
        let data = object.section_data(id.name()).unwrap_or(&[]);
        Ok(gimli::EndianSlice::new(data, endian))
    };

    let dwarf = match gimli::Dwarf::load(load_section) {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };

    let mut out: Vec<RawSymbol> = Vec::new();
    let mut iter = dwarf.units();
    while let Some(header) = iter.next().unwrap_or(None) {
        let Ok(unit) = dwarf.unit(header) else { continue };
        let unit_ref = unit.unit_ref(&dwarf);
        let mut entries = unit_ref.entries();
        while let Some((_, entry)) = entries.next_dfs().unwrap_or(None) {
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            let mut name: Option<String> = None;
            let mut low_pc: Option<u64> = None;
            let mut high_pc: Option<u64> = None;
            let mut high_pc_offset: Option<u64> = None;

            let mut attrs = entry.attrs();
            while let Some(attr) = attrs.next().unwrap_or(None) {
                match attr.name() {
                    gimli::DW_AT_name => {
                        if let Ok(s) = unit_ref.attr_string(attr.value()) {
                            if let Ok(t) = s.to_string() {
                                name = Some(t.to_string());
                            }
                        }
                    }
                    gimli::DW_AT_linkage_name => {
                        if name.is_none() {
                            if let Ok(s) = unit_ref.attr_string(attr.value()) {
                                if let Ok(t) = s.to_string() {
                                    name = Some(t.to_string());
                                }
                            }
                        }
                    }
                    gimli::DW_AT_low_pc => {
                        if let gimli::AttributeValue::Addr(a) = attr.value() {
                            low_pc = Some(a);
                        }
                    }
                    gimli::DW_AT_high_pc => match attr.value() {
                        gimli::AttributeValue::Addr(a) => high_pc = Some(a),
                        gimli::AttributeValue::Udata(o) => high_pc_offset = Some(o),
                        _ => {}
                    },
                    _ => {}
                }
            }

            if let (Some(n), Some(lo)) = (name, low_pc) {
                let size = match (high_pc, high_pc_offset) {
                    (Some(hi), _) => hi.saturating_sub(lo),
                    (_, Some(off)) => off,
                    _ => 0,
                };
                out.push(RawSymbol {
                    name: n,
                    address: lo,
                    size,
                    kind: SymbolKind::Function,
                });
            }
        }
    }
    Ok(out)
}

/// Load PDB symbols for a side-loaded `.pdb` file matching a PE.
pub fn load_pdb_symbols(pdb_path: &std::path::Path, image_base: u64) -> Result<Vec<RawSymbol>> {
    use pdb::FallibleIterator;
    let file = std::fs::File::open(pdb_path)?;
    let mut pdb = pdb::PDB::open(file)?;
    let address_map = pdb.address_map()?;
    let symbol_table = pdb.global_symbols()?;
    let mut iter = symbol_table.iter();
    let mut out = Vec::new();
    while let Some(symbol) = iter.next()? {
        let parsed = match symbol.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let pdb::SymbolData::Public(data) = parsed {
            if !data.function {
                continue;
            }
            if let Some(rva) = data.offset.to_rva(&address_map) {
                out.push(RawSymbol {
                    name: data.name.to_string().into_owned(),
                    address: image_base + u32::from(rva) as u64,
                    size: 0,
                    kind: SymbolKind::Function,
                });
            }
        }
    }
    Ok(out)
}

// ---------- minimal in-place section index for DWARF loading ----------

struct ObjectSections<'a> {
    sections: Vec<(String, &'a [u8])>,
}

impl<'a> ObjectSections<'a> {
    fn section_data(&self, name: &str) -> Option<&'a [u8]> {
        self.sections
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| *d)
    }
}

fn object_for_dwarf(bytes: &[u8]) -> Option<ObjectSections<'_>> {
    let obj = goblin::Object::parse(bytes).ok()?;
    let mut sections: Vec<(String, &[u8])> = Vec::new();
    match obj {
        goblin::Object::Elf(elf) => {
            for sh in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                if !name.starts_with(".debug_") && !name.starts_with(".zdebug_") {
                    continue;
                }
                let start = sh.sh_offset as usize;
                let end = start.saturating_add(sh.sh_size as usize).min(bytes.len());
                if start < bytes.len() {
                    sections.push((name.to_string(), &bytes[start..end]));
                }
            }
        }
        goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            for segment in macho.segments.iter() {
                for (sect, data) in segment.sections().unwrap_or_default() {
                    let raw_name =
                        std::str::from_utf8(&sect.sectname).unwrap_or("").trim_end_matches('\0');
                    if !raw_name.starts_with("__debug_") {
                        continue;
                    }
                    let gimli_name = format!(".{}", &raw_name[2..]);
                    sections.push((gimli_name, data));
                }
            }
        }
        _ => return None,
    }
    Some(ObjectSections { sections })
}
