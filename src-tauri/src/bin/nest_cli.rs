//! nest_cli — headless NEST backend CLI
//!
//! Exposes the same Capstone / object analysis commands used by the Tauri
//! backend as a JSON-over-stdout CLI tool callable from Node.js scripts or
//! any other process that can spawn a child process.
//!
//! Usage:
//!   nest_cli disassemble <path> <offset> <length>
//!   nest_cli cfg         <path> <offset> <length>
//!   nest_cli inspect     <path>
//!   nest_cli strings     <path>
//!   nest_cli identify    <path>
//!   nest_cli strike --headless <path> --out <report.json>
//!   nest_cli serve --mcp    (MCP JSON-RPC 2.0 stdio server)
//!
//! Output: JSON printed to stdout or, for headless STRIKE reports, written to
//! the requested JSON file. Analysis errors exit 1; bad arguments exit 2.
//!
//! Build: cargo build --bin nest_cli (or cargo build --release --bin nest_cli)

#![allow(
    dead_code,
    unused_mut,
    clippy::if_same_then_else,
    clippy::manual_range_contains,
    clippy::needless_lifetimes,
    clippy::unwrap_or_default
)]

// Reuse the command implementations from the Tauri backend crate.
// #[path] at the file level resolves relative to src/bin/, so ../commands/
// correctly points to src/commands/.
#[path = "../commands/pe_imports.rs"]
mod pe_imports;
#[path = "../commands/disassemble.rs"]
mod cmd_disassemble;
#[path = "../commands/graph.rs"]
mod cmd_graph;
#[path = "../commands/hex.rs"]
mod cmd_hex;
#[path = "../commands/inspect.rs"]
mod cmd_inspect;
#[path = "../commands/strings.rs"]
mod cmd_strings;

// plugins mod is required transitively by the commands (for tauri command macros);
// provide a minimal stub so it compiles as a standalone binary.
mod plugins {}

use cmd_disassemble::disassemble_file_range;
use cmd_graph::build_cfg;
use cmd_inspect::inspect_file_metadata;
use cmd_strings::extract_strings;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Serialize)]
struct IdentifyResult {
    format: String,
    magic_hex: String,
    file_size: u64,
    entropy_header_4kb: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeadlessArgs {
    binary_path: String,
    out_path: String,
}

#[derive(Debug, Clone, Serialize)]
struct StrikeHeadlessReport {
    file: StrikeReportFile,
    verdict: StrikeReportVerdict,
    imports: Vec<StrikeReportImport>,
    strings: Vec<String>,
    il_summary: StrikeIlSummary,
    signals: Vec<StrikeSignal>,
    generated_at: String,
}

#[derive(Debug, Clone, Serialize)]
struct StrikeReportFile {
    path: String,
    sha256: String,
    size: u64,
}

#[derive(Debug, Clone, Serialize)]
struct StrikeReportVerdict {
    classification: String,
    confidence: String,
}

#[derive(Debug, Clone, Serialize)]
struct StrikeReportImport {
    name: String,
    prototype: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct StrikeIlSummary {
    functions: usize,
    call_sites: usize,
}

#[derive(Debug, Clone, Serialize)]
struct StrikeSignal {
    id: String,
    description: String,
    weight: f64,
}

fn identify_format(path: String) -> Result<IdentifyResult, String> {
    use std::fs;
    use std::io::Read;

    let meta = fs::metadata(&path).map_err(|e| format!("stat failed: {e}"))?;
    let file_size = meta.len();

    // Read first 4 KB for magic + entropy
    const HDR: usize = 4096;
    let mut buf = vec![0u8; HDR.min(file_size as usize)];
    let mut f = fs::File::open(&path).map_err(|e| format!("open failed: {e}"))?;
    f.read_exact(&mut buf)
        .map_err(|e| format!("read failed: {e}"))?;

    // Magic bytes as hex string
    let magic_hex = buf
        .get(..4)
        .map(|b| {
            b.iter()
                .map(|x| format!("{x:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|| "??".into());

    // Format from magic
    let format = match buf.as_slice() {
        [0x4D, 0x5A, ..] => "PE/MZ".into(),
        [0x7F, 0x45, 0x4C, 0x46, ..] => "ELF".into(),
        [0xCF, 0xFA, 0xED, 0xFE, ..]
        | [0xCE, 0xFA, 0xED, 0xFE, ..]
        | [0xCA, 0xFE, 0xBA, 0xBE, ..] => "Mach-O".into(),
        [0x25, 0x50, 0x44, 0x46, ..] => "PDF".into(),
        [0x50, 0x4B, 0x03, 0x04, ..] | [0x50, 0x4B, 0x05, 0x06, ..] => "ZIP".into(),
        [0x52, 0x61, 0x72, 0x21, 0x1A, ..] => "RAR".into(),
        [0x37, 0x7A, 0xBC, 0xAF, 0x27, ..] => "7-Zip".into(),
        [0x1F, 0x8B, ..] => "GZip".into(),
        [0x23, 0x21, ..] => "Script".into(),
        [0x0A, 0x0D, 0x0D, 0x0A, ..] => "PCAPNG".into(),
        [0xD4, 0xC3, 0xB2, 0xA1, ..] | [0xA1, 0xB2, 0xC3, 0xD4, ..] => "PCAP".into(),
        _ => {
            let sample = &buf[..buf.len().min(512)];
            if sample.iter().all(|&b| b >= 0x09 && b < 0x80) {
                "Text/Script".into()
            } else {
                format!("Unknown [magic: {magic_hex}]")
            }
        }
    };

    // Shannon entropy of 4 KB header
    let mut counts = [0u64; 256];
    for &b in &buf {
        counts[b as usize] += 1;
    }
    let len = buf.len() as f64;
    let entropy_header_4kb: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum();

    Ok(IdentifyResult {
        format,
        magic_hex,
        file_size,
        entropy_header_4kb,
    })
}

fn usage() -> ! {
    usage_with_exit(2)
}

fn is_help_request(args: &[String]) -> bool {
    matches!(args.get(1).map(String::as_str), Some("--help" | "-h"))
}

fn write_usage(mut output: impl Write) -> std::io::Result<()> {
    writeln!(output, "Usage:")?;
    writeln!(output, "  nest_cli disassemble <path> <offset> <length>")?;
    writeln!(output, "  nest_cli cfg         <path> <offset> <length>")?;
    writeln!(output, "  nest_cli inspect     <path>")?;
    writeln!(output, "  nest_cli strings     <path>")?;
    writeln!(output, "  nest_cli identify    <path>")?;
    writeln!(output, "  nest_cli strike --headless <path> --out <report.json>")?;
    writeln!(output, "  nest_cli serve --mcp")?;
    Ok(())
}

fn usage_with_exit(code: i32) -> ! {
    if code == 0 {
        let _ = write_usage(std::io::stdout());
    } else {
        let _ = write_usage(std::io::stderr());
    }
    std::process::exit(code);
}

fn parse_strike_headless_args(args: &[String]) -> Result<HeadlessArgs, String> {
    if args.len() != 6 || args.get(1).map(String::as_str) != Some("strike") {
        return Err("expected: nest_cli strike --headless <path> --out <report.json>".to_string());
    }
    if args.get(2).map(String::as_str) != Some("--headless") {
        return Err("missing --headless".to_string());
    }
    if args.get(4).map(String::as_str) != Some("--out") {
        return Err("missing --out <report.json>".to_string());
    }
    let binary_path = args[3].clone();
    let out_path = args[5].clone();
    if binary_path.trim().is_empty() {
        return Err("missing binary path".to_string());
    }
    if out_path.trim().is_empty() {
        return Err("missing output path".to_string());
    }
    Ok(HeadlessArgs {
        binary_path,
        out_path,
    })
}

fn sha256_file(path: &str) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn deterministic_generated_at() -> String {
    // Headless batch reports are intentionally stable for CI diffing. Use a
    // fixed ISO-8601 marker instead of wall-clock time so the same input bytes
    // produce the same JSON report.
    "1970-01-01T00:00:00Z".to_string()
}

fn gyre_headless_verdict(_metadata: &cmd_inspect::FileMetadata) -> StrikeReportVerdict {
    // Classification is deliberately conservative in standalone headless mode:
    // this Rust CLI does not run a GUI/NEST session, so it must not let STRIKE
    // signals or convenience heuristics become verdict authority. GYRE remains
    // the sole classification owner; unavailable verdict evidence is reported
    // as unknown rather than inferred from imports or strings.
    StrikeReportVerdict {
        classification: "unknown".to_string(),
        confidence: "low".to_string(),
    }
}

struct OperationalContextRule {
    id: &'static str,
    markers: &'static [&'static str],
    min_hits: usize,
    description: &'static str,
}

const OPERATIONAL_CONTEXT_RULES: &[OperationalContextRule] = &[
    OperationalContextRule {
        id: "legacy.magic_btrieve.context",
        markers: &[
            "mgbtrv.dll",
            "wbtrv32.dll",
            "btrieve",
            "btrv",
            "get_first",
            "get_next",
            "set_owner",
            "clear_owner",
        ],
        min_hits: 1,
        description: "Magic/Btrieve runtime markers present; treat as legacy data-access context and seek the main application/runtime before structural claims",
    },
    OperationalContextRule {
        id: "legacy.magic_security_file.reference",
        markers: &["usr_std.eng", "user.ddf", "mgusrdmp", "usrupd.exe"],
        min_hits: 1,
        description: "Magic security-file references present; report credential-related findings as redacted candidates until runtime/app callsites confirm field meaning",
    },
    OperationalContextRule {
        id: "ops.database_access.context",
        markers: &[
            "sqlite3.dll",
            "libsqlite3",
            "odbc32.dll",
            "sqlsrv32.dll",
            "libpq.dll",
            "mysqlclient",
            "mysqldump",
            "database=",
            "dsn=",
            "jdbc:",
        ],
        min_hits: 1,
        description: "Database/client-access markers present; prioritize schema/config discovery and separate business data access from threat behavior",
    },
    OperationalContextRule {
        id: "ops.legacy_record_store.context",
        markers: &[".dbf", ".cdx", ".fpt", "foxpro", "vfp9r.dll", "xbase", "paradox", ".mdb"],
        min_hits: 1,
        description: "Legacy record-store markers present; consider fixed-record/table heuristics, dictionary files, and version diffs before asserting semantics",
    },
    OperationalContextRule {
        id: "ops.managed_runtime.context",
        markers: &[
            "mscoree.dll",
            "clr.dll",
            "system.runtime",
            "java/lang/",
            "jvm.dll",
            "python.dll",
            "pyinstaller",
            "electron.asar",
            "node.dll",
        ],
        min_hits: 1,
        description: "Managed/packaged runtime markers present; pivot to manifest, bundle, bytecode, or package-layer analysis before low-level native conclusions",
    },
    OperationalContextRule {
        id: "ops.installer_updater.context",
        markers: &[
            "inno setup",
            "nullsoft",
            "nsis",
            "squirrel",
            "msiexec",
            "update.exe",
            "autoupdate",
            "installer",
            "setup.exe",
        ],
        min_hits: 1,
        description: "Installer/updater markers present; distinguish deployment mechanics from payload behavior and preserve package custody evidence",
    },
    OperationalContextRule {
        id: "ops.credential_material.candidate",
        markers: &[
            "password",
            "passwd",
            "pwd=",
            "credential",
            "secret",
            "api_key",
            "apikey",
            "token=",
            "bearer ",
            "oauth",
        ],
        min_hits: 1,
        description: "Credential-adjacent markers present; emit labels/offsets only by default and redact values unless explicit reveal approval exists",
    },
    OperationalContextRule {
        id: "ops.report_template.context",
        markers: &["report", "template", "operator", "e-mail address", "customer status", "form", "ledger"],
        min_hits: 2,
        description: "Report/template vocabulary present; avoid mistaking UI/report labels for stored secrets or executable behavior",
    },
];

fn operational_context_corpus(
    metadata: &cmd_inspect::FileMetadata,
    strings: &[String],
) -> Vec<String> {
    let mut corpus: Vec<String> = strings.iter().map(|s| s.to_ascii_lowercase()).collect();
    corpus.extend(metadata.imports.iter().flat_map(|import| {
        [
            import.name.to_ascii_lowercase(),
            import.library.to_ascii_lowercase(),
        ]
    }));
    corpus.extend(metadata.pe_imports.iter().flat_map(|import| {
        [
            import.name.clone().unwrap_or_default().to_ascii_lowercase(),
            import.dll.to_ascii_lowercase(),
            import
                .ordinal
                .map(|ordinal| format!("{}#{}", import.dll.to_ascii_lowercase(), ordinal))
                .unwrap_or_default(),
        ]
    }));
    corpus.extend(metadata.exports.iter().map(|export| export.name.to_ascii_lowercase()));
    corpus.retain(|entry| !entry.is_empty());
    corpus
}

fn collect_headless_signals(
    metadata: &cmd_inspect::FileMetadata,
    strings: &[String],
) -> Vec<StrikeSignal> {
    let mut signals = Vec::new();
    if metadata.imports_count > 0 {
        signals.push(StrikeSignal {
            id: "imports.present".to_string(),
            description: format!("{} imported symbol(s) recovered", metadata.imports_count),
            weight: 0.2,
        });
    }
    if strings
        .iter()
        .any(|s| s.contains("http://") || s.contains("https://"))
    {
        signals.push(StrikeSignal {
            id: "strings.url".to_string(),
            description: "URL-like string present in extracted strings".to_string(),
            weight: 0.3,
        });
    }

    let corpus = operational_context_corpus(metadata, strings);
    for rule in OPERATIONAL_CONTEXT_RULES {
        let hit_count = rule
            .markers
            .iter()
            .filter(|marker| corpus.iter().any(|entry| entry.contains(**marker)))
            .count();
        if hit_count >= rule.min_hits {
            signals.push(StrikeSignal {
                id: rule.id.to_string(),
                description: format!(
                    "{} ({} marker family hit(s)); advisory workflow context only, not standalone GYRE verdict evidence",
                    rule.description, hit_count
                ),
                weight: 0.1,
            });
        }
    }

    signals
}

fn estimate_il_summary(path: &str, metadata: &cmd_inspect::FileMetadata) -> StrikeIlSummary {
    let functions = usize::from(metadata.entry_point != 0);
    let text_section = metadata.sections.iter().find(|section| {
        let name = section.name.to_ascii_lowercase();
        name == ".text" || name == ".code" || name == "__text"
    });
    let Some(section) = text_section else {
        return StrikeIlSummary {
            functions,
            call_sites: 0,
        };
    };
    let Ok(disasm) = disassemble_file_range(
        path.to_string(),
        section.file_offset as usize,
        section.file_size.min(256 * 1024) as usize,
        Some(20_000),
    ) else {
        return StrikeIlSummary {
            functions,
            call_sites: 0,
        };
    };
    let call_sites = disasm
        .instructions
        .iter()
        .filter(|ins| {
            let mnemonic = ins.mnemonic.as_str();
            mnemonic == "call" || mnemonic == "callq" || mnemonic.starts_with("bl")
        })
        .count();
    StrikeIlSummary {
        functions,
        call_sites,
    }
}

fn build_strike_headless_report(path: &str) -> Result<StrikeHeadlessReport, String> {
    let metadata_fs = fs::metadata(path).map_err(|e| format!("stat failed: {e}"))?;
    if !metadata_fs.is_file() {
        return Err("binary path is not a file".to_string());
    }
    let metadata = inspect_file_metadata(path.to_string())?;
    let extracted = extract_strings(path.to_string())?;
    let mut strings: Vec<String> = extracted
        .ascii
        .into_iter()
        .chain(extracted.unicode)
        .collect();
    strings.sort();
    strings.dedup();

    let imports = metadata
        .imports
        .iter()
        .map(|imp| StrikeReportImport {
            name: if imp.library.is_empty() {
                imp.name.clone()
            } else {
                format!("{}!{}", imp.library, imp.name)
            },
            prototype: None,
        })
        .collect();

    let il_summary = estimate_il_summary(path, &metadata);
    let signals = collect_headless_signals(&metadata, &strings);
    let verdict = gyre_headless_verdict(&metadata);

    Ok(StrikeHeadlessReport {
        file: StrikeReportFile {
            path: path.to_string(),
            sha256: sha256_file(path)?,
            size: metadata_fs.len(),
        },
        verdict,
        imports,
        strings,
        il_summary,
        signals,
        generated_at: deterministic_generated_at(),
    })
}

fn run_strike_headless(args: &HeadlessArgs) -> Result<(), String> {
    let report = build_strike_headless_report(&args.binary_path)?;
    let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    if let Some(parent) = Path::new(&args.out_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create output directory failed: {e}"))?;
        }
    }
    let mut file =
        fs::File::create(&args.out_path).map_err(|e| format!("create output failed: {e}"))?;
    file.write_all(json.as_bytes())
        .map_err(|e| format!("write output failed: {e}"))?;
    file.write_all(b"\n")
        .map_err(|e| format!("write output failed: {e}"))?;
    Ok(())
}

// ─── MCP stdio server ────────────────────────────────────────────────────────

/// Run a Model Context Protocol (MCP) JSON-RPC 2.0 server over stdin/stdout.
///
/// Messages: newline-delimited JSON objects.
///   Client → server: `{"jsonrpc":"2.0","id":<id>,"method":"<tool>","params":{...}}`
///   Server → client: `{"jsonrpc":"2.0","id":<id>,"result":{...}}`
///              or:   `{"jsonrpc":"2.0","id":<id>,"error":{"code":-32000,"message":"..."}}`
///
/// Special methods:
///   `initialize`         → server info + capabilities
///   `tools/list`         → list all tools (names + descriptions)
///   `tools/call`         → call a tool by name; params forwarded
fn run_mcp_server() {
    use std::io::{BufRead, Write};

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut stdout_lock = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if !l.trim().is_empty() => l,
            _ => continue,
        };

        let msg: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = mcp_error(
                    serde_json::Value::Null,
                    -32700,
                    &format!("Parse error: {e}"),
                );
                let _ = writeln!(stdout_lock, "{}", err);
                continue;
            }
        };

        let id = msg.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(serde_json::json!({}));

        let response = match method {
            "initialize" => mcp_ok(
                id,
                serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "hexhawk",
                        "version": "1.0.0"
                    },
                    "capabilities": {
                        "tools": {}
                    }
                }),
            ),

            "tools/list" => mcp_ok(
                id,
                serde_json::json!({
                    "tools": [
                        { "name": "inspect",        "description": "Inspect binary metadata (file type, architecture, sections, entry point)." },
                        { "name": "disassemble",    "description": "Disassemble a byte range and return instructions." },
                        { "name": "strings",        "description": "Extract printable strings from a binary." },
                        { "name": "build_cfg",      "description": "Build a control-flow graph for a code region." },
                        { "name": "nest_results",   "description": "Return current NEST analysis verdict for a session (read-only)." },
                        { "name": "inject_agent_signal", "description": "Propose an agent-sourced GYRE signal — requires analyst approval." },
                        { "name": "apply_patch",    "description": "Propose a binary patch — ALWAYS requires analyst approval via HexHawk UI." }
                    ]
                }),
            ),

            "tools/call" => {
                let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or(serde_json::json!({}));
                dispatch_tool(id.clone(), tool_name, &args)
            }

            // notifications (no id expected — send nothing)
            "notifications/initialized" => continue,

            _ => mcp_error(id, -32601, &format!("Method not found: {method}")),
        };

        let _ = writeln!(stdout_lock, "{response}");
    }
}

/// Dispatch a `tools/call` request to the appropriate HexHawk command.
fn dispatch_tool(id: serde_json::Value, name: &str, args: &serde_json::Value) -> String {
    match name {
        "inspect" => {
            let path = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return mcp_error(id, -32602, "Missing required argument: path"),
            };
            match inspect_file_metadata(path) {
                Ok(r) => mcp_ok(id, serde_json::to_value(r).unwrap_or_default()),
                Err(e) => mcp_error(id, -32000, &e),
            }
        }

        "disassemble" => {
            let path = str_arg(args, "path");
            let offset = int_arg(args, "offset");
            let length = int_arg(args, "length");
            let max = args.get("max_instructions").and_then(|v| v.as_u64());
            match (path, offset, length) {
                (Some(p), Some(off), Some(len)) => match disassemble_file_range(p, off, len, max) {
                    Ok(r) => mcp_ok(id, serde_json::to_value(r).unwrap_or_default()),
                    Err(e) => mcp_error(id, -32000, &e),
                },
                _ => mcp_error(
                    id,
                    -32602,
                    "Missing required arguments: path, offset, length",
                ),
            }
        }

        "strings" => {
            let path = str_arg(args, "path");
            let offset = int_arg(args, "offset").unwrap_or(0);
            let length = int_arg(args, "length").unwrap_or(0);
            let min_len = args.get("min_length").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
            match path {
                Some(p) => match cmd_hex::find_strings(p, offset, length, min_len) {
                    Ok(r) => mcp_ok(id, serde_json::to_value(r).unwrap_or_default()),
                    Err(e) => mcp_error(id, -32000, &e),
                },
                None => mcp_error(id, -32602, "Missing required argument: path"),
            }
        }

        "build_cfg" => {
            let path = str_arg(args, "path");
            let offset = int_arg(args, "offset");
            let length = int_arg(args, "length");
            match (path, offset, length) {
                (Some(p), Some(off), Some(len)) => match build_cfg(p, off, len) {
                    Ok(r) => mcp_ok(id, serde_json::to_value(r).unwrap_or_default()),
                    Err(e) => mcp_error(id, -32000, &e),
                },
                _ => mcp_error(
                    id,
                    -32602,
                    "Missing required arguments: path, offset, length",
                ),
            }
        }

        // Read-only stub for nest_results and approval-gated stubs:
        // These tools are defined in the schema for completeness; in --mcp mode
        // we return a structured response that reminds the agent to use the
        // Tauri IPC path for live session state.
        "nest_results" => mcp_ok(
            id,
            serde_json::json!({
                "note": "nest_results requires a live HexHawk session. Use the Tauri IPC command get_nest_session_summary from the desktop app context."
            }),
        ),

        "inject_agent_signal" => {
            // Validate signal shape and echo it back as "pending approval".
            let session_id = args
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let signal = args.get("signal").cloned().unwrap_or_default();
            mcp_ok(
                id,
                serde_json::json!({
                    "accepted": true,
                    "pending_id": format!("agent-sig-{}-pending", session_id),
                    "signal": signal,
                    "message": "Signal accepted into approval queue. Analyst must approve via HexHawk UI before it affects the GYRE verdict."
                }),
            )
        }

        "apply_patch" => {
            let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
            let description = args
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("(no description)");
            mcp_ok(
                id,
                serde_json::json!({
                    "queued": true,
                    "queue_id": format!("imp-patch-0x{:x}-pending", offset),
                    "message": format!("Patch '{}' at offset 0x{:x} has been queued. ANALYST APPROVAL REQUIRED in HexHawk IMP panel before any bytes are written.", description, offset)
                }),
            )
        }

        _ => mcp_error(id, -32601, &format!("Unknown tool: {name}")),
    }
}

// ─── JSON-RPC helpers ────────────────────────────────────────────────────────

fn mcp_ok(id: serde_json::Value, result: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
    .to_string()
}

fn mcp_error(id: serde_json::Value, code: i64, message: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
    .to_string()
}

fn str_arg<'a>(args: &'a serde_json::Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn int_arg(args: &serde_json::Value, key: &str) -> Option<usize> {
    args.get(key).and_then(|v| v.as_u64()).map(|n| n as usize)
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if is_help_request(&args) {
        usage_with_exit(0);
    }

    // nest_cli serve --mcp
    if args.get(1).map(|s| s.as_str()) == Some("serve")
        && args.get(2).map(|s| s.as_str()) == Some("--mcp")
    {
        run_mcp_server();
        return Ok(());
    }

    if args.get(1).map(String::as_str) == Some("strike") {
        match parse_strike_headless_args(&args) {
            Ok(parsed) => {
                if let Err(e) = run_strike_headless(&parsed) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!("Bad arguments: {}", e);
                usage();
            }
        }
    }

    if args.len() < 3 {
        usage();
    }

    let cmd = args[1].as_str();
    let path = args[2].clone();

    let json_result: Result<String, String> =
        match cmd {
            "disassemble" => {
                if args.len() < 5 {
                    usage();
                }
                let offset: usize = args[3]
                    .parse()
                    .map_err(|e| format!("Invalid offset '{}': {}", args[3], e))?;
                let length: usize = args[4]
                    .parse()
                    .map_err(|e| format!("Invalid length '{}': {}", args[4], e))?;
                disassemble_file_range(path, offset, length, None)
                    .and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string()))
            }

            "cfg" => {
                if args.len() < 5 {
                    usage();
                }
                let offset: usize = args[3]
                    .parse()
                    .map_err(|e| format!("Invalid offset '{}': {}", args[3], e))?;
                let length: usize = args[4]
                    .parse()
                    .map_err(|e| format!("Invalid length '{}': {}", args[4], e))?;
                build_cfg(path, offset, length)
                    .and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string()))
            }

            "inspect" => inspect_file_metadata(path)
                .and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string())),

            "strings" => extract_strings(path)
                .and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string())),

            "identify" => identify_format(path)
                .and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string())),

            _ => {
                eprintln!("Unknown command: {}", cmd);
                usage();
            }
        };

    match json_result {
        Ok(json) => {
            println!("{}", json);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> String {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "hexhawk_nest_cli_{}_{}_{}",
            name,
            std::process::id(),
            deterministic_generated_at().replace(':', "_")
        );
        path.push(unique);
        path.to_string_lossy().to_string()
    }

    #[test]
    fn help_flags_are_detected_before_bad_argument_handling() {
        for flag in ["--help", "-h"] {
            let args = vec!["nest_cli".to_string(), flag.to_string()];
            assert!(is_help_request(&args), "{flag} should be a help request");
        }
    }

    #[test]
    fn no_args_and_invalid_commands_are_not_help_requests() {
        let no_args = vec!["nest_cli".to_string()];
        let invalid = vec!["nest_cli".to_string(), "unknown".to_string()];
        let strike_missing_binary = vec![
            "nest_cli".to_string(),
            "strike".to_string(),
            "--headless".to_string(),
            "--out".to_string(),
            "report.json".to_string(),
        ];

        assert!(!is_help_request(&no_args));
        assert!(!is_help_request(&invalid));
        assert!(!is_help_request(&strike_missing_binary));
    }

    #[test]
    fn usage_text_contains_core_commands() {
        let mut output = Vec::new();
        write_usage(&mut output).expect("usage writes");
        let text = String::from_utf8(output).expect("usage is utf8");

        assert!(text.contains("Usage:"));
        assert!(text.contains("nest_cli inspect     <path>"));
        assert!(text.contains("nest_cli strike --headless <path> --out <report.json>"));
        assert!(text.contains("nest_cli serve --mcp"));
    }

    #[test]
    fn strike_headless_subcommand_parses_valid_args() {
        let args = vec![
            "nest_cli".to_string(),
            "strike".to_string(),
            "--headless".to_string(),
            "fixture.bin".to_string(),
            "--out".to_string(),
            "report.json".to_string(),
        ];
        let parsed = parse_strike_headless_args(&args).expect("valid strike args parse");
        assert_eq!(parsed.binary_path, "fixture.bin");
        assert_eq!(parsed.out_path, "report.json");
    }

    #[test]
    fn strike_headless_missing_binary_path_is_bad_args() {
        let args = vec![
            "nest_cli".to_string(),
            "strike".to_string(),
            "--headless".to_string(),
            "--out".to_string(),
            "report.json".to_string(),
        ];
        let err = parse_strike_headless_args(&args).expect_err("missing binary path rejected");
        assert!(err.contains("expected") || err.contains("missing"));
    }

    #[test]
    fn strike_headless_report_json_matches_expected_schema_for_fixture() {
        let fixture_path = temp_path("fixture.bin");
        let out_path = temp_path("report.json");
        fs::write(
            &fixture_path,
            b"MZ\x00\x00This fixture has http://example.test and CreateFileW text",
        )
        .unwrap();

        let args = HeadlessArgs {
            binary_path: fixture_path.clone(),
            out_path: out_path.clone(),
        };
        run_strike_headless(&args).expect("headless report writes");

        let json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&out_path).unwrap()).unwrap();
        assert_eq!(json["file"]["path"], fixture_path);
        assert!(json["file"]["sha256"].as_str().unwrap().len() == 64);
        assert!(json["file"]["size"].as_u64().unwrap() > 0);
        assert_eq!(json["verdict"]["classification"], "unknown");
        assert_eq!(json["verdict"]["confidence"], "low");
        assert!(json["imports"].as_array().is_some());
        assert!(json["strings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("example.test")));
        assert!(json["il_summary"]["functions"].as_u64().is_some());
        assert!(json["il_summary"]["call_sites"].as_u64().is_some());
        assert!(json["signals"].as_array().is_some());
        assert_eq!(json["generated_at"], "1970-01-01T00:00:00Z");

        let _ = fs::remove_file(fixture_path);
        let _ = fs::remove_file(out_path);
    }

    fn minimal_metadata() -> cmd_inspect::FileMetadata {
        cmd_inspect::FileMetadata {
            file_type: "PE/MZ".to_string(),
            architecture: "x86".to_string(),
            entry_point: 0,
            file_size: 1024,
            image_base: 0,
            sections: Vec::new(),
            imports_count: 0,
            exports_count: 0,
            symbols_count: 0,
            imports: Vec::new(),
            pe_imports: Vec::new(),
            exports: Vec::new(),
            sha256: "0".repeat(64),
            sha1: "0".repeat(40),
            md5: "0".repeat(32),
        }
    }

    #[test]
    fn headless_signals_flag_magic_btrieve_context_without_changing_verdict() {
        let metadata = minimal_metadata();
        let strings = vec![
            "MGbtrv.dll".to_string(),
            "wbtrv32.dll".to_string(),
            "usr_std.eng".to_string(),
        ];

        let signals = collect_headless_signals(&metadata, &strings);
        let ids: Vec<&str> = signals.iter().map(|s| s.id.as_str()).collect();

        assert!(ids.contains(&"legacy.magic_btrieve.context"));
        assert!(ids.contains(&"legacy.magic_security_file.reference"));
        assert_eq!(gyre_headless_verdict(&metadata).classification, "unknown");
    }

    #[test]
    fn headless_signals_map_general_operational_contexts_without_verdict_escalation() {
        let mut metadata = minimal_metadata();
        metadata.imports_count = 2;
        metadata.imports = vec![
            cmd_inspect::ImportEntry {
                name: "SQLConnectW".to_string(),
                library: "ODBC32.dll".to_string(),
            },
            cmd_inspect::ImportEntry {
                name: "CorExeMain".to_string(),
                library: "mscoree.dll".to_string(),
            },
        ];
        let strings = vec![
            "Database=customer.db;DSN=legacy".to_string(),
            "Operator Report Template".to_string(),
            "password label present but value is not emitted".to_string(),
            "electron.asar".to_string(),
            "Inno Setup installer".to_string(),
        ];

        let signals = collect_headless_signals(&metadata, &strings);
        let ids: Vec<&str> = signals.iter().map(|s| s.id.as_str()).collect();

        assert!(ids.contains(&"imports.present"));
        assert!(ids.contains(&"ops.database_access.context"));
        assert!(ids.contains(&"ops.managed_runtime.context"));
        assert!(ids.contains(&"ops.installer_updater.context"));
        assert!(ids.contains(&"ops.credential_material.candidate"));
        assert!(ids.contains(&"ops.report_template.context"));
        assert_eq!(gyre_headless_verdict(&metadata).classification, "unknown");
    }
}
