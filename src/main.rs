//! lancer-ghidra
//! Rust clone of ghidra. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-ghidra", version, about = "Rust clone of ghidra")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-ghidra - scaffold ready. Implement per plan.md.");
    Ok(())
}
