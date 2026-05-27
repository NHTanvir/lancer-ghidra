// List the 10 largest functions in the binary.
// Run with:  lancer-ghidra script <binary> examples/list_top_functions.rhai

print("arch:  " + ctx.arch());
print("entry: 0x" + ctx.entry().to_string());

let fns = ctx.list_functions();
fns.sort(|a, b| if a.size > b.size { -1 } else { 1 });

let n = if fns.len() < 10 { fns.len() } else { 10 };
print("\nTop " + n + " largest functions:");
for i in 0..n {
    let f = fns[i];
    print("  size=" + f.size + "  entry=0x" + f.entry.to_string() + "  " + f.name);
}
