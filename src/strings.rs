//! ASCII + UTF-16LE string extraction with virtual-address tagging.

use crate::loader::Binary;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Encoding {
    Ascii,
    Utf16Le,
}

#[derive(Debug, Clone, Serialize)]
pub struct FoundString {
    pub vaddr: u64,
    pub encoding: Encoding,
    pub value: String,
}

/// Default minimum string length, matching the `strings(1)` tool.
pub const DEFAULT_MIN_LEN: usize = 4;

/// Extract printable ASCII and UTF-16LE strings from the binary's loaded
/// sections, tagging each with the virtual address it lives at.
pub fn extract(bin: &Binary, min_len: usize) -> Vec<FoundString> {
    let mut found = Vec::new();

    for sect in &bin.sections {
        if sect.size == 0 {
            continue;
        }
        let bytes = bin.section_bytes(sect);
        if bytes.is_empty() {
            continue;
        }
        find_ascii(sect.vaddr, bytes, min_len, &mut found);
        find_utf16le(sect.vaddr, bytes, min_len, &mut found);
    }

    found
}

fn find_ascii(base: u64, bytes: &[u8], min_len: usize, out: &mut Vec<FoundString>) {
    let mut start: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let printable = matches!(b, 0x20..=0x7e | b'\t');
        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= min_len {
                if let Ok(text) = std::str::from_utf8(&bytes[s..i]) {
                    out.push(FoundString {
                        vaddr: base + s as u64,
                        encoding: Encoding::Ascii,
                        value: text.to_string(),
                    });
                }
            }
        }
        i += 1;
    }
    if let Some(s) = start {
        if bytes.len() - s >= min_len {
            if let Ok(text) = std::str::from_utf8(&bytes[s..]) {
                out.push(FoundString {
                    vaddr: base + s as u64,
                    encoding: Encoding::Ascii,
                    value: text.to_string(),
                });
            }
        }
    }
}

fn find_utf16le(base: u64, bytes: &[u8], min_len: usize, out: &mut Vec<FoundString>) {
    if bytes.len() < 2 {
        return;
    }
    let mut i = 0;
    while i + 1 < bytes.len() {
        let c0 = bytes[i];
        let c1 = bytes[i + 1];
        if c1 == 0 && matches!(c0, 0x20..=0x7e | 0x09) {
            let start = i;
            let mut chars = Vec::new();
            let mut j = i;
            while j + 1 < bytes.len() {
                let a = bytes[j];
                let b = bytes[j + 1];
                if b == 0 && matches!(a, 0x20..=0x7e | 0x09) {
                    chars.push(a);
                    j += 2;
                } else {
                    break;
                }
            }
            if chars.len() >= min_len {
                let text: String = chars.iter().map(|&b| b as char).collect();
                out.push(FoundString {
                    vaddr: base + start as u64,
                    encoding: Encoding::Utf16Le,
                    value: text,
                });
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii() {
        let bytes = b"\x00\x00Hello, World!\x00garbage\x00password\x00";
        let mut out = Vec::new();
        find_ascii(0x1000, bytes, 4, &mut out);
        let vals: Vec<&str> = out.iter().map(|s| s.value.as_str()).collect();
        assert!(vals.contains(&"Hello, World!"));
        assert!(vals.contains(&"password"));
    }

    #[test]
    fn finds_utf16le() {
        let mut bytes = Vec::new();
        for c in b"WideText" {
            bytes.push(*c);
            bytes.push(0);
        }
        bytes.push(0);
        bytes.push(0);
        let mut out = Vec::new();
        find_utf16le(0x2000, &bytes, 4, &mut out);
        assert!(out.iter().any(|s| s.value == "WideText"));
    }
}
