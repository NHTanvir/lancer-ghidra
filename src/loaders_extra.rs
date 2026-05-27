//! Extra loaders for formats not covered by `goblin`:
//!   - raw binary (just take the bytes, you tell us the arch + base)
//!   - Intel HEX (.hex)
//!   - Motorola S-record (.srec / .s19 / .s28 / .s37)
//!   - WebAssembly (.wasm)
//!
//! Each loader produces a fully-formed `Binary` so downstream analyses keep
//! working without special cases.

use crate::loader::{Arch, Binary, Endian, Format, Import, Section};
use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;

pub fn load_raw(path: PathBuf, bytes: Vec<u8>, arch: Arch, base: u64) -> Binary {
    let sect = Section {
        name: ".raw".to_string(),
        vaddr: base,
        size: bytes.len() as u64,
        file_offset: 0,
        file_size: bytes.len() as u64,
        readable: true,
        writable: false,
        executable: true,
    };
    Binary {
        path,
        bytes,
        format: Format::Unknown,
        arch,
        endian: Endian::Little,
        entry: base,
        image_base: base,
        sections: vec![sect],
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        libraries: Vec::new(),
    }
}

pub fn load_intel_hex(path: PathBuf, text: &str, arch: Arch) -> Result<Binary> {
    let mut data: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut ext_addr: u32 = 0;
    let mut entry: u32 = 0;

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if !line.starts_with(':') || line.len() < 11 {
            continue;
        }
        let raw: Vec<u8> = hex::decode(&line[1..])
            .with_context(|| format!("intel-hex: bad hex on line {}", lineno + 1))?;
        if raw.len() < 5 {
            continue;
        }
        let count = raw[0] as usize;
        let addr = u16::from_be_bytes([raw[1], raw[2]]) as u32;
        let rectype = raw[3];
        let payload = &raw[4..4 + count];
        match rectype {
            0x00 => data.push(((ext_addr << 16) | addr, payload.to_vec())),
            0x01 => break,
            0x02 => {
                ext_addr = u16::from_be_bytes([payload[0], payload[1]]) as u32 * 16;
            }
            0x04 => {
                ext_addr = u16::from_be_bytes([payload[0], payload[1]]) as u32;
            }
            0x05 => {
                entry = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            }
            _ => {}
        }
    }
    if data.is_empty() {
        return Err(anyhow!("intel-hex: no data records"));
    }

    let base = data.iter().map(|(a, _)| *a).min().unwrap_or(0) as u64;
    let end = data
        .iter()
        .map(|(a, p)| *a as u64 + p.len() as u64)
        .max()
        .unwrap_or(base);
    let size = end - base;

    let mut flat = vec![0u8; size as usize];
    for (a, payload) in &data {
        let off = (*a as u64 - base) as usize;
        flat[off..off + payload.len()].copy_from_slice(payload);
    }

    let sect = Section {
        name: ".hex".to_string(),
        vaddr: base,
        size,
        file_offset: 0,
        file_size: size,
        readable: true,
        writable: false,
        executable: true,
    };
    Ok(Binary {
        path,
        bytes: flat,
        format: Format::Unknown,
        arch,
        endian: Endian::Little,
        entry: if entry == 0 { base } else { entry as u64 },
        image_base: base,
        sections: vec![sect],
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        libraries: Vec::new(),
    })
}

pub fn load_srec(path: PathBuf, text: &str, arch: Arch) -> Result<Binary> {
    let mut data: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut entry: u64 = 0;

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.len() < 4 || !line.starts_with('S') {
            continue;
        }
        let kind = line.as_bytes()[1] as char;
        let raw: Vec<u8> = hex::decode(&line[2..])
            .with_context(|| format!("srec: bad hex on line {}", lineno + 1))?;
        if raw.is_empty() {
            continue;
        }
        let count = raw[0] as usize;
        if raw.len() < 1 + count {
            continue;
        }
        let (addr_len, has_payload) = match kind {
            '1' => (2, true),
            '2' => (3, true),
            '3' => (4, true),
            '7' => (4, false),
            '8' => (3, false),
            '9' => (2, false),
            _ => continue,
        };
        let addr_bytes = &raw[1..1 + addr_len];
        let mut addr: u64 = 0;
        for b in addr_bytes {
            addr = (addr << 8) | *b as u64;
        }
        if has_payload {
            let payload = &raw[1 + addr_len..1 + count - 1];
            data.push((addr, payload.to_vec()));
        } else {
            entry = addr;
        }
    }
    if data.is_empty() {
        return Err(anyhow!("srec: no data records"));
    }

    let base = data.iter().map(|(a, _)| *a).min().unwrap_or(0);
    let end = data
        .iter()
        .map(|(a, p)| *a + p.len() as u64)
        .max()
        .unwrap_or(base);
    let size = end - base;

    let mut flat = vec![0u8; size as usize];
    for (a, payload) in &data {
        let off = (*a - base) as usize;
        flat[off..off + payload.len()].copy_from_slice(payload);
    }

    let sect = Section {
        name: ".srec".to_string(),
        vaddr: base,
        size,
        file_offset: 0,
        file_size: size,
        readable: true,
        writable: false,
        executable: true,
    };
    Ok(Binary {
        path,
        bytes: flat,
        format: Format::Unknown,
        arch,
        endian: Endian::Little,
        entry: if entry == 0 { base } else { entry },
        image_base: base,
        sections: vec![sect],
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        libraries: Vec::new(),
    })
}

/// WebAssembly. We surface the module's functions as `Import`s (host
/// imports), report the code section as our `.text`, and report the data
/// section as `.data`. We don't disassemble WASM bytecode — `iced-x86`
/// won't help here — but we cover the loader / sectioning / imports view.
pub fn load_wasm(path: PathBuf, bytes: Vec<u8>) -> Result<Binary> {
    use wasmparser::{Parser, Payload};

    let mut sections: Vec<Section> = Vec::new();
    let mut imports: Vec<Import> = Vec::new();
    let mut next_vaddr: u64 = 0x10_0000;

    for payload in Parser::new(0).parse_all(&bytes) {
        let payload = payload.context("wasmparser: parse failed")?;
        match payload {
            Payload::CodeSectionStart { range, size, .. } => {
                sections.push(Section {
                    name: ".text".to_string(),
                    vaddr: next_vaddr,
                    size: size as u64,
                    file_offset: range.start as u64,
                    file_size: size as u64,
                    readable: true,
                    writable: false,
                    executable: true,
                });
                next_vaddr += size as u64 + 0x1000;
            }
            Payload::DataSection(reader) => {
                let range = reader.range();
                sections.push(Section {
                    name: ".data".to_string(),
                    vaddr: next_vaddr,
                    size: (range.end - range.start) as u64,
                    file_offset: range.start as u64,
                    file_size: (range.end - range.start) as u64,
                    readable: true,
                    writable: true,
                    executable: false,
                });
                next_vaddr += (range.end - range.start) as u64 + 0x1000;
            }
            Payload::ImportSection(reader) => {
                for imp in reader {
                    let imp = imp.context("wasmparser: bad import")?;
                    imports.push(Import {
                        name: imp.name.to_string(),
                        library: Some(imp.module.to_string()),
                        address: None,
                    });
                }
            }
            _ => {}
        }
    }

    Ok(Binary {
        path,
        bytes,
        format: Format::Unknown,
        arch: Arch::Unknown,
        endian: Endian::Little,
        entry: 0,
        image_base: 0,
        sections,
        symbols: Vec::new(),
        imports,
        exports: Vec::new(),
        libraries: Vec::new(),
    })
}
