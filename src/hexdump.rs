//! Classic `xxd`-style hex+ascii dump.

use std::fmt::Write as _;

pub fn render(base_addr: u64, bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4);
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let addr = base_addr + (i * 16) as u64;
        let _ = write!(out, "{:016x}  ", addr);

        for j in 0..16 {
            if j == 8 {
                out.push(' ');
            }
            match chunk.get(j) {
                Some(b) => {
                    let _ = write!(out, "{:02x} ", b);
                }
                None => out.push_str("   "),
            }
        }

        out.push(' ');
        out.push('|');
        for b in chunk {
            let c = *b;
            out.push(if (0x20..0x7f).contains(&c) { c as char } else { '.' });
        }
        out.push('|');
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line() {
        let out = render(0x1000, b"Hello, World!\n");
        assert!(out.contains("0000000000001000"));
        assert!(out.contains("48 65 6c 6c 6f"));
        assert!(out.contains("|Hello, World!.|"));
    }

    #[test]
    fn multi_line() {
        let bytes: Vec<u8> = (0..32).collect();
        let out = render(0, &bytes);
        assert_eq!(out.lines().count(), 2);
    }
}
