//! Embedded localhost web UI — a single self-contained HTML page that talks
//! to a built-in HTTP server (no separate Svelte build, no node, no npm).
//!
//! Routes:
//!   GET /              → index HTML
//!   GET /api/info      → binary metadata
//!   GET /api/sections  → sections list
//!   GET /api/functions → detected functions
//!   GET /api/strings   → extracted strings
//!   GET /api/disasm?addr=...&len=... → disassembly
//!   GET /api/xrefs?addr=...        → cross-references to address
//!
//! Same Lancer-standard pattern: ships as a single .exe.

use crate::ai;
use crate::cfg::{build_call_graph, build_cfg};
use crate::disasm::{disassemble, disassemble_va};
use crate::functions::{analyze, AnalysisOptions, Function};
use crate::llm;
use crate::loader::Binary;
use crate::strings::{extract, FoundString, DEFAULT_MIN_LEN};
use crate::xref::{build_index, XrefIndex};
use anyhow::Result;
use serde::Serialize;
use std::sync::Arc;
use tiny_http::{Header, Method, Response, Server};

const INDEX_HTML: &str = include_str!("web_index.html");

struct Ctx {
    bin: Binary,
    functions: Vec<Function>,
    xrefs: XrefIndex,
    strings: Vec<FoundString>,
}

pub fn serve(bin: Binary, addr: &str) -> Result<()> {
    let server = Server::http(addr).map_err(|e| anyhow::anyhow!("could not bind {addr}: {e}"))?;
    eprintln!("lancer-ghidra web UI listening on http://{}", addr);

    let funcs = analyze(&bin, &AnalysisOptions::default());
    let strings = extract(&bin, DEFAULT_MIN_LEN);

    let mut per_function = Vec::new();
    for f in &funcs {
        if let Some(b) = bin.read_va(f.entry, f.size as usize) {
            if let Ok(ins) = disassemble(bin.arch, f.entry, b) {
                per_function.push((f.clone(), ins));
            }
        }
    }
    let xref_inputs: Vec<(&Function, &[crate::disasm::Insn])> =
        per_function.iter().map(|(f, v)| (f, v.as_slice())).collect();
    let xrefs = build_index(xref_inputs);

    let ctx = Arc::new(Ctx { bin, functions: funcs, xrefs, strings });

    for req in server.incoming_requests() {
        let ctx = Arc::clone(&ctx);
        let response = route(&ctx, &req);
        let _ = req.respond(response);
    }
    Ok(())
}

fn route(ctx: &Ctx, req: &tiny_http::Request) -> Response<std::io::Cursor<Vec<u8>>> {
    if req.method() != &Method::Get {
        return text_response(405, "method not allowed");
    }
    let url = req.url();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p, q),
        None => (url, ""),
    };

    match path {
        "/" => html_response(INDEX_HTML),
        "/api/info" => {
            #[derive(Serialize)]
            struct Info<'a> {
                path: String,
                format: String,
                arch: &'a str,
                entry: u64,
                image_base: u64,
                section_count: usize,
                function_count: usize,
                import_count: usize,
                export_count: usize,
            }
            json_response(&Info {
                path: ctx.bin.path.display().to_string(),
                format: format!("{:?}", ctx.bin.format),
                arch: ctx.bin.arch.as_str(),
                entry: ctx.bin.entry,
                image_base: ctx.bin.image_base,
                section_count: ctx.bin.sections.len(),
                function_count: ctx.functions.len(),
                import_count: ctx.bin.imports.len(),
                export_count: ctx.bin.exports.len(),
            })
        }
        "/api/sections" => json_response(&ctx.bin.sections),
        "/api/functions" => json_response(&ctx.functions),
        "/api/imports" => json_response(&ctx.bin.imports),
        "/api/exports" => json_response(&ctx.bin.exports),
        "/api/strings" => {
            let strs = extract(&ctx.bin, DEFAULT_MIN_LEN);
            json_response(&strs)
        }
        "/api/disasm" => {
            let params = parse_query(query);
            let addr = params
                .get("addr")
                .and_then(|s| parse_u64(s))
                .unwrap_or(ctx.bin.entry);
            let len = params
                .get("len")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(256);
            if let Some(f) = ctx.functions.iter().find(|f| f.entry == addr) {
                let bytes = ctx.bin.read_va(f.entry, f.size as usize).unwrap_or(&[]);
                let insns = disassemble(ctx.bin.arch, f.entry, bytes).unwrap_or_default();
                return json_response(&insns);
            }
            let insns = disassemble_va(&ctx.bin, addr, len).unwrap_or_default();
            json_response(&insns)
        }
        "/api/xrefs" => {
            let params = parse_query(query);
            let addr = params.get("addr").and_then(|s| parse_u64(s)).unwrap_or(0);
            #[derive(Serialize)]
            struct X {
                to: Vec<u64>,
                from: Vec<u64>,
            }
            json_response(&X {
                to: ctx.xrefs.references_to(addr),
                from: ctx.xrefs.references_from(addr),
            })
        }
        "/api/cfg" => {
            let params = parse_query(query);
            let addr = params.get("addr").and_then(|s| parse_u64(s)).unwrap_or(0);
            if let Some(f) = ctx.functions.iter().find(|f| f.entry == addr) {
                let bytes = ctx.bin.read_va(f.entry, f.size as usize).unwrap_or(&[]);
                let ins = disassemble(ctx.bin.arch, f.entry, bytes).unwrap_or_default();
                let cfg = build_cfg(f.entry, &ins);
                return json_response(&cfg);
            }
            json_response(&serde_json::json!({"error": "no such function"}))
        }
        "/api/callgraph" => {
            let cg = build_call_graph(&ctx.functions);
            json_response(&cg.to_json())
        }
        "/api/ai-decompile" => {
            let params = parse_query(query);
            let addr = params.get("addr").and_then(|s| parse_u64(s)).unwrap_or(ctx.bin.entry);
            let send = params.get("send").map(|s| s == "1").unwrap_or(false);
            let model = params.get("model").cloned().unwrap_or_else(|| "claude-opus-4-7".to_string());
            let Some(f) = ctx.functions.iter().find(|f| f.entry == addr) else {
                return text_response(404, "no function at that address");
            };
            let bytes = ctx.bin.read_va(f.entry, f.size as usize).unwrap_or(&[]);
            let insns = disassemble(ctx.bin.arch, f.entry, bytes).unwrap_or_default();
            let prompt = ai::build_prompt(&ai::DecompileContext {
                bin: &ctx.bin,
                func: f,
                insns: &insns,
                xrefs: &ctx.xrefs,
                all_strings: &ctx.strings,
                all_functions: &ctx.functions,
            });
            if send {
                let mut cfg = llm::LlmConfig::default();
                cfg.model = model;
                match llm::send_prompt(&prompt, &cfg) {
                    Ok(reply) => {
                        let h = Header::from_bytes(&b"Content-Type"[..], &b"text/plain; charset=utf-8"[..]).unwrap();
                        return Response::from_string(reply).with_status_code(200).with_header(h);
                    }
                    Err(e) => return text_response(500, &format!("LLM error: {e}")),
                }
            }
            let h = Header::from_bytes(&b"Content-Type"[..], &b"text/plain; charset=utf-8"[..]).unwrap();
            Response::from_string(prompt).with_status_code(200).with_header(h)
        }
        _ => text_response(404, "not found"),
    }
}

fn parse_query(s: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for pair in s.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let v = urlencoding::decode(v).map(|c| c.into_owned()).unwrap_or_else(|_| v.to_string());
            out.insert(k.to_string(), v);
        }
    }
    out
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(stripped, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn html_response(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let h = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap();
    Response::from_string(body).with_status_code(200).with_header(h)
}

fn json_response<T: Serialize>(v: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string());
    let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    Response::from_string(body).with_status_code(200).with_header(h)
}

fn text_response(code: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(msg).with_status_code(code)
}
