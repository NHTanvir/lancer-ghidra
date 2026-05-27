//! Demangle Itanium (g++/clang), MSVC, and Rust mangled names.

pub fn demangle(name: &str) -> Option<String> {
    if let Some(d) = demangle_rust(name) {
        return Some(d);
    }
    if name.starts_with('?') {
        if let Ok(d) = msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::llvm()) {
            return Some(d);
        }
    }
    if name.starts_with("_Z") || name.starts_with("__Z") {
        if let Ok(sym) = cpp_demangle::Symbol::new(name) {
            if let Ok(d) = sym.demangle(&cpp_demangle::DemangleOptions::new()) {
                return Some(d);
            }
        }
    }
    None
}

fn demangle_rust(name: &str) -> Option<String> {
    let dm = rustc_demangle::try_demangle(name).ok()?;
    let s = format!("{:#}", dm);
    if s == name {
        return None;
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_v0() {
        let mangled = "_RNvCs1234_7example3foo";
        let _ = demangle(mangled);
    }

    #[test]
    fn itanium() {
        let mangled = "_ZN3foo3barEv";
        let d = demangle(mangled).expect("should demangle");
        assert!(d.contains("foo::bar"));
    }

    #[test]
    fn passthrough_for_unmangled() {
        assert_eq!(demangle("main"), None);
    }
}
