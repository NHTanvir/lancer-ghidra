//! Binary loader: ELF / PE / Mach-O via `goblin`.
//!
//! Loads a binary from disk, identifies its format and architecture, and
//! exposes sections/segments + a virtual-address → file-offset mapping that
//! downstream modules (disasm, xrefs, strings) consume.

use anyhow::{anyhow, Context, Result};
use goblin::Object;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Format {
    Elf,
    Pe,
    MachO,
    Archive,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Mips,
    Mips64,
    PowerPc,
    PowerPc64,
    RiscV,
    Sparc,
    Unknown,
}

impl Arch {
    #[allow(dead_code)]
    pub fn pointer_size(self) -> usize {
        match self {
            Arch::X86_64 | Arch::Aarch64 | Arch::Mips64 | Arch::PowerPc64 => 8,
            Arch::X86 | Arch::Arm | Arch::Mips | Arch::PowerPc | Arch::RiscV | Arch::Sparc => 4,
            Arch::Unknown => 8,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Arm => "arm",
            Arch::Aarch64 => "aarch64",
            Arch::Mips => "mips",
            Arch::Mips64 => "mips64",
            Arch::PowerPc => "ppc",
            Arch::PowerPc64 => "ppc64",
            Arch::RiscV => "riscv",
            Arch::Sparc => "sparc",
            Arch::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// A loaded segment of the binary mapped at some virtual address.
#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Import {
    pub name: String,
    pub library: Option<String>,
    pub address: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Export {
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RawSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: SymbolKind,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Object,
    Section,
    File,
    Other,
}

/// A loaded binary: metadata + raw bytes + section table.
pub struct Binary {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub format: Format,
    pub arch: Arch,
    pub endian: Endian,
    pub entry: u64,
    pub image_base: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<RawSymbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub libraries: Vec<String>,
}

impl Binary {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::from_bytes(path.to_path_buf(), bytes)
    }

    pub fn from_bytes(path: PathBuf, bytes: Vec<u8>) -> Result<Self> {
        let mut meta = {
            let obj = Object::parse(&bytes)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            match obj {
                Object::Elf(elf) => parse_elf_meta(&bytes, elf),
                Object::PE(pe) => parse_pe_meta(pe),
                Object::Mach(mach) => parse_mach_meta(mach),
                Object::Archive(_) => return Err(anyhow!("archive files (.a/.ar) not supported yet")),
                _ => return Err(anyhow!("unknown / unsupported binary format")),
            }?
        };
        meta.path = path;
        meta.bytes = bytes;
        Ok(meta)
    }

}

fn parse_elf_meta(bytes: &[u8], elf: goblin::elf::Elf<'_>) -> Result<Binary> {
    let _ = bytes;
    Binary::from_elf(elf)
}

fn parse_pe_meta(pe: goblin::pe::PE<'_>) -> Result<Binary> {
    Binary::from_pe(pe)
}

fn parse_mach_meta(mach: goblin::mach::Mach<'_>) -> Result<Binary> {
    Binary::from_mach(mach)
}

impl Binary {
    fn from_elf(elf: goblin::elf::Elf<'_>) -> Result<Self> {
        let arch = match elf.header.e_machine {
            goblin::elf::header::EM_386 => Arch::X86,
            goblin::elf::header::EM_X86_64 => Arch::X86_64,
            goblin::elf::header::EM_ARM => Arch::Arm,
            goblin::elf::header::EM_AARCH64 => Arch::Aarch64,
            goblin::elf::header::EM_MIPS => {
                if elf.is_64 { Arch::Mips64 } else { Arch::Mips }
            }
            goblin::elf::header::EM_PPC => Arch::PowerPc,
            goblin::elf::header::EM_PPC64 => Arch::PowerPc64,
            goblin::elf::header::EM_RISCV => Arch::RiscV,
            goblin::elf::header::EM_SPARC | goblin::elf::header::EM_SPARCV9 => Arch::Sparc,
            _ => Arch::Unknown,
        };

        let endian = if elf.little_endian { Endian::Little } else { Endian::Big };
        let entry = elf.entry;

        let image_base = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|ph| ph.p_vaddr)
            .min()
            .unwrap_or(0);

        let mut sections = Vec::new();
        for sh in &elf.section_headers {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("")
                .to_string();
            if sh.sh_addr == 0 && sh.sh_size == 0 {
                continue;
            }
            let flags = sh.sh_flags;
            let exec = (flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR)) != 0;
            let writable = (flags & u64::from(goblin::elf::section_header::SHF_WRITE)) != 0;
            let alloc = (flags & u64::from(goblin::elf::section_header::SHF_ALLOC)) != 0;
            sections.push(Section {
                name,
                vaddr: sh.sh_addr,
                size: sh.sh_size,
                file_offset: sh.sh_offset,
                file_size: sh.sh_size,
                readable: alloc,
                writable,
                executable: exec,
            });
        }

        let mut symbols = Vec::new();
        for sym in elf.syms.iter() {
            let name = elf
                .strtab
                .get_at(sym.st_name)
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            let kind = match sym.st_type() {
                goblin::elf::sym::STT_FUNC => SymbolKind::Function,
                goblin::elf::sym::STT_OBJECT => SymbolKind::Object,
                goblin::elf::sym::STT_SECTION => SymbolKind::Section,
                goblin::elf::sym::STT_FILE => SymbolKind::File,
                _ => SymbolKind::Other,
            };
            if sym.st_value == 0 && kind == SymbolKind::Other {
                continue;
            }
            symbols.push(RawSymbol {
                name,
                address: sym.st_value,
                size: sym.st_size,
                kind,
            });
        }
        for sym in elf.dynsyms.iter() {
            let name = elf
                .dynstrtab
                .get_at(sym.st_name)
                .unwrap_or("")
                .to_string();
            if name.is_empty() || sym.st_value == 0 {
                continue;
            }
            let kind = match sym.st_type() {
                goblin::elf::sym::STT_FUNC => SymbolKind::Function,
                goblin::elf::sym::STT_OBJECT => SymbolKind::Object,
                _ => SymbolKind::Other,
            };
            symbols.push(RawSymbol {
                name,
                address: sym.st_value,
                size: sym.st_size,
                kind,
            });
        }

        let mut imports = Vec::new();
        for sym in elf.dynsyms.iter() {
            if sym.is_import() {
                let name = elf
                    .dynstrtab
                    .get_at(sym.st_name)
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() {
                    imports.push(Import { name, library: None, address: None });
                }
            }
        }

        let exports = elf
            .dynsyms
            .iter()
            .filter(|s| !s.is_import() && s.st_value != 0)
            .filter_map(|s| {
                let name = elf.dynstrtab.get_at(s.st_name).unwrap_or("").to_string();
                if name.is_empty() {
                    None
                } else {
                    Some(Export { name, address: s.st_value })
                }
            })
            .collect();

        let libraries = elf.libraries.iter().map(|s| s.to_string()).collect();

        Ok(Self {
            path: PathBuf::new(),
            bytes: Vec::new(),
            format: Format::Elf,
            arch,
            endian,
            entry,
            image_base,
            sections,
            symbols,
            imports,
            exports,
            libraries,
        })
    }

    fn from_pe(pe: goblin::pe::PE<'_>) -> Result<Self> {
        let arch = match pe.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_X86 => Arch::X86,
            goblin::pe::header::COFF_MACHINE_X86_64 => Arch::X86_64,
            goblin::pe::header::COFF_MACHINE_ARM => Arch::Arm,
            goblin::pe::header::COFF_MACHINE_ARM64 => Arch::Aarch64,
            _ => Arch::Unknown,
        };

        let image_base = pe
            .header
            .optional_header
            .map(|opt| opt.windows_fields.image_base)
            .unwrap_or(0);

        let entry = image_base + pe.entry as u64;

        let mut sections = Vec::new();
        for sect in &pe.sections {
            let name = sect.name().unwrap_or("?").to_string();
            let chars = sect.characteristics;
            let exec = chars & 0x2000_0000 != 0; // IMAGE_SCN_MEM_EXECUTE
            let readable = chars & 0x4000_0000 != 0; // IMAGE_SCN_MEM_READ
            let writable = chars & 0x8000_0000 != 0; // IMAGE_SCN_MEM_WRITE
            sections.push(Section {
                name,
                vaddr: image_base + sect.virtual_address as u64,
                size: sect.virtual_size as u64,
                file_offset: sect.pointer_to_raw_data as u64,
                file_size: sect.size_of_raw_data as u64,
                readable,
                writable,
                executable: exec,
            });
        }

        let imports = pe
            .imports
            .iter()
            .map(|imp| Import {
                name: imp.name.to_string(),
                library: Some(imp.dll.to_string()),
                address: Some(image_base + imp.rva as u64),
            })
            .collect();

        let exports = pe
            .exports
            .iter()
            .filter_map(|e| {
                e.name.map(|n| Export {
                    name: n.to_string(),
                    address: image_base + e.rva as u64,
                })
            })
            .collect();

        let libraries = pe.libraries.iter().map(|s| s.to_string()).collect();

        Ok(Self {
            path: PathBuf::new(),
            bytes: Vec::new(),
            format: Format::Pe,
            arch,
            endian: Endian::Little,
            entry,
            image_base,
            sections,
            symbols: Vec::new(),
            imports,
            exports,
            libraries,
        })
    }

    fn from_mach(mach: goblin::mach::Mach<'_>) -> Result<Self> {
        let macho = match mach {
            goblin::mach::Mach::Binary(m) => m,
            goblin::mach::Mach::Fat(fat) => {
                let mut chosen = None;
                for entry in fat.into_iter() {
                    let arch = match entry {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    if let goblin::mach::SingleArch::MachO(m) = arch {
                        chosen = Some(m);
                        break;
                    }
                }
                chosen.ok_or_else(|| anyhow!("no usable arch in fat Mach-O"))?
            }
        };

        let arch = match macho.header.cputype() {
            goblin::mach::constants::cputype::CPU_TYPE_X86 => Arch::X86,
            goblin::mach::constants::cputype::CPU_TYPE_X86_64 => Arch::X86_64,
            goblin::mach::constants::cputype::CPU_TYPE_ARM => Arch::Arm,
            goblin::mach::constants::cputype::CPU_TYPE_ARM64 => Arch::Aarch64,
            _ => Arch::Unknown,
        };

        let entry = macho.entry;

        let mut sections = Vec::new();
        let mut image_base = u64::MAX;
        for segment in macho.segments.iter() {
            let seg_name = segment.name().unwrap_or("?").to_string();
            for (sect, _data) in segment.sections().unwrap_or_default() {
                let name = format!(
                    "{}.{}",
                    seg_name,
                    std::str::from_utf8(&sect.sectname).unwrap_or("?").trim_end_matches('\0')
                );
                let flags = sect.flags;
                // S_ATTR_PURE_INSTRUCTIONS = 0x80000000
                let exec = (flags & 0x8000_0000) != 0
                    || seg_name == "__TEXT";
                sections.push(Section {
                    name,
                    vaddr: sect.addr,
                    size: sect.size,
                    file_offset: u64::from(sect.offset),
                    file_size: sect.size,
                    readable: true,
                    writable: seg_name == "__DATA" || seg_name == "__DATA_CONST",
                    executable: exec,
                });
                if sect.addr > 0 && sect.addr < image_base {
                    image_base = sect.addr;
                }
            }
        }
        if image_base == u64::MAX {
            image_base = 0;
        }

        Ok(Self {
            path: PathBuf::new(),
            bytes: Vec::new(),
            format: Format::MachO,
            arch,
            endian: Endian::Little,
            entry,
            image_base,
            sections,
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            libraries: Vec::new(),
        })
    }

    /// Translate a virtual address to the file offset, if it lies inside any section.
    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<usize> {
        for s in &self.sections {
            if s.size == 0 {
                continue;
            }
            if vaddr >= s.vaddr && vaddr < s.vaddr + s.size {
                let off = s.file_offset + (vaddr - s.vaddr);
                if (off as usize) < self.bytes.len() {
                    return Some(off as usize);
                }
            }
        }
        None
    }

    /// Find the section containing a virtual address.
    pub fn section_at(&self, vaddr: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.size > 0 && vaddr >= s.vaddr && vaddr < s.vaddr + s.size)
    }

    /// Read `len` bytes starting at the given virtual address.
    pub fn read_va(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        let off = self.vaddr_to_offset(vaddr)?;
        let end = off.checked_add(len)?;
        if end > self.bytes.len() {
            return None;
        }
        Some(&self.bytes[off..end])
    }

    /// Read a slice of bytes from a section, clipped to the section bounds.
    pub fn section_bytes(&self, sect: &Section) -> &[u8] {
        let start = sect.file_offset as usize;
        let end = start.saturating_add(sect.file_size as usize).min(self.bytes.len());
        if start >= self.bytes.len() {
            return &[];
        }
        &self.bytes[start..end]
    }

    /// Iterator over executable sections.
    pub fn code_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.executable && s.size > 0)
    }
}
