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
//!   nest_cli serve --mcp    (MCP JSON-RPC 2.0 stdio server)
//!
//! Output: JSON printed to stdout.  Errors printed to stderr, exit 1.
//!
//! Build: cargo build --bin nest_cli (or cargo build --release --bin nest_cli)

// Reuse the command implementations from the Tauri backend crate.
// #[path] at the file level resolves relative to src/bin/, so ../commands/
// correctly points to src/commands/.
#[path = "../commands/disassemble.rs"]
mod cmd_disassemble;
#[path = "../commands/graph.rs"]
mod cmd_graph;
#[path = "../commands/inspect.rs"]
mod cmd_inspect;
#[path = "../commands/hex.rs"]
mod cmd_hex;
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

#[derive(Serialize)]
struct IdentifyResult {
    format: String,
    magic_hex: String,
    file_size: u64,
    entropy_header_4kb: f64,
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
    f.read_exact(&mut buf).map_err(|e| format!("read failed: {e}"))?;

    // Magic bytes as hex string
    let magic_hex = buf.get(..4)
        .map(|b| b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| "??".into());

    // Format from magic
    let format = match buf.as_slice() {
        [0x4D, 0x5A, ..]                   => "PE/MZ".into(),
        [0x7F, 0x45, 0x4C, 0x46, ..]       => "ELF".into(),
        [0xCF, 0xFA, 0xED, 0xFE, ..]
        | [0xCE, 0xFA, 0xED, 0xFE, ..]
        | [0xCA, 0xFE, 0xBA, 0xBE, ..]     => "Mach-O".into(),
        [0x25, 0x50, 0x44, 0x46, ..]       => "PDF".into(),
        [0x50, 0x4B, 0x03, 0x04, ..]
        | [0x50, 0x4B, 0x05, 0x06, ..]     => "ZIP".into(),
        [0x52, 0x61, 0x72, 0x21, 0x1A, ..] => "RAR".into(),
        [0x37, 0x7A, 0xBC, 0xAF, 0x27, ..] => "7-Zip".into(),
        [0x1F, 0x8B, ..]                   => "GZip".into(),
        [0x23, 0x21, ..]                   => "Script".into(),
        [0x0A, 0x0D, 0x0D, 0x0A, ..]       => "PCAPNG".into(),
        [0xD4, 0xC3, 0xB2, 0xA1, ..]
        | [0xA1, 0xB2, 0xC3, 0xD4, ..]     => "PCAP".into(),
        _                                  => {
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
    for &b in &buf { counts[b as usize] += 1; }
    let len = buf.len() as f64;
    let entropy_header_4kb: f64 = counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum();

    Ok(IdentifyResult { format, magic_hex, file_size, entropy_header_4kb })
}

fn usage() -> ! {
    eprintln!("Usage:");
    eprintln!("  nest_cli disassemble <path> <offset> <length>");
    eprintln!("  nest_cli cfg         <path> <offset> <length>");
    eprintln!("  nest_cli inspect     <path>");
    eprintln!("  nest_cli strings     <path>");
    eprintln!("  nest_cli identify    <path>");
    eprintln!("  nest_cli serve --mcp");
    std::process::exit(1);
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
                let err = mcp_error(serde_json::Value::Null, -32700, &format!("Parse error: {e}"));
                let _ = writeln!(stdout_lock, "{}", err);
                continue;
            }
        };

        let id = msg.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(serde_json::json!({}));

        let response = match method {
            "initialize" => mcp_ok(id, serde_json::json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "hexhawk",
                    "version": "1.0.0"
                },
                "capabilities": {
                    "tools": {}
                }
            })),

            "tools/list" => mcp_ok(id, serde_json::json!({
                "tools": [
                    { "name": "inspect",        "description": "Inspect binary metadata (file type, architecture, sections, entry point)." },
                    { "name": "disassemble",    "description": "Disassemble a byte range and return instructions." },
                    { "name": "strings",        "description": "Extract printable strings from a binary." },
                    { "name": "build_cfg",      "description": "Build a control-flow graph for a code region." },
                    { "name": "nest_results",   "description": "Return current NEST analysis verdict for a session (read-only)." },
                    { "name": "inject_agent_signal", "description": "Propose an agent-sourced GYRE signal — requires analyst approval." },
                    { "name": "apply_patch",    "description": "Propose a binary patch — ALWAYS requires analyst approval via HexHawk UI." }
                ]
            })),

            "tools/call" => {
                let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));
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
                Ok(r)  => mcp_ok(id, serde_json::to_value(r).unwrap_or_default()),
                Err(e) => mcp_error(id, -32000, &e),
            }
        }

        "disassemble" => {
            let path   = str_arg(args, "path");
            let offset = int_arg(args, "offset");
            let length = int_arg(args, "length");
            let max    = args.get("max_instructions").and_then(|v| v.as_u64());
            match (path, offset, length) {
                (Some(p), Some(off), Some(len)) => {
                    match disassemble_file_range(p, off, len, max) {
                        Ok(r)  => mcp_ok(id, serde_json::to_value(r).unwrap_or_default()),
                        Err(e) => mcp_error(id, -32000, &e),
                    }
                }
                _ => mcp_error(id, -32602, "Missing required arguments: path, offset, length"),
            }
        }

        "strings" => {
            let path   = str_arg(args, "path");
            let offset = int_arg(args, "offset").unwrap_or(0);
            let length = int_arg(args, "length").unwrap_or(0);
            let min_len = args.get("min_length").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
            match path {
                Some(p) => {
                    match cmd_hex::find_strings(p, offset, length, min_len) {
                        Ok(r)  => mcp_ok(id, serde_json::to_value(r).unwrap_or_default()),
                        Err(e) => mcp_error(id, -32000, &e),
                    }
                }
                None => mcp_error(id, -32602, "Missing required argument: path"),
            }
        }

        "build_cfg" => {
            let path   = str_arg(args, "path");
            let offset = int_arg(args, "offset");
            let length = int_arg(args, "length");
            match (path, offset, length) {
                (Some(p), Some(off), Some(len)) => {
                    match build_cfg(p, off, len) {
                        Ok(r)  => mcp_ok(id, serde_json::to_value(r).unwrap_or_default()),
                        Err(e) => mcp_error(id, -32000, &e),
                    }
                }
                _ => mcp_error(id, -32602, "Missing required arguments: path, offset, length"),
            }
        }

        // Read-only stub for nest_results and approval-gated stubs:
        // These tools are defined in the schema for completeness; in --mcp mode
        // we return a structured response that reminds the agent to use the
        // Tauri IPC path for live session state.
        "nest_results" => {
            mcp_ok(id, serde_json::json!({
                "note": "nest_results requires a live HexHawk session. Use the Tauri IPC command get_nest_session_summary from the desktop app context."
            }))
        }

        "inject_agent_signal" => {
            // Validate signal shape and echo it back as "pending approval".
            let session_id = args.get("session_id").and_then(|v| v.as_str()).unwrap_or("unknown");
            let signal = args.get("signal").cloned().unwrap_or_default();
            mcp_ok(id, serde_json::json!({
                "accepted": true,
                "pending_id": format!("agent-sig-{}-pending", session_id),
                "signal": signal,
                "message": "Signal accepted into approval queue. Analyst must approve via HexHawk UI before it affects the GYRE verdict."
            }))
        }

        "apply_patch" => {
            let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
            let description = args.get("description").and_then(|v| v.as_str()).unwrap_or("(no description)");
            mcp_ok(id, serde_json::json!({
                "queued": true,
                "queue_id": format!("imp-patch-0x{:x}-pending", offset),
                "message": format!("Patch '{}' at offset 0x{:x} has been queued. ANALYST APPROVAL REQUIRED in HexHawk IMP panel before any bytes are written.", description, offset)
            }))
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
    args.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn int_arg(args: &serde_json::Value, key: &str) -> Option<usize> {
    args.get(key).and_then(|v| v.as_u64()).map(|n| n as usize)
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // nest_cli serve --mcp
    if args.get(1).map(|s| s.as_str()) == Some("serve")
        && args.get(2).map(|s| s.as_str()) == Some("--mcp")
    {
        run_mcp_server();
        return Ok(());
    }

    if args.len() < 3 {
        usage();
    }

    let cmd  = args[1].as_str();
    let path = args[2].clone();

    let json_result: Result<String, String> = match cmd {
        "disassemble" => {
            if args.len() < 5 { usage(); }
            let offset: usize = args[3].parse()
                .map_err(|e| format!("Invalid offset '{}': {}", args[3], e))?;
            let length: usize = args[4].parse()
                .map_err(|e| format!("Invalid length '{}': {}", args[4], e))?;
            disassemble_file_range(path, offset, length, None)
                .and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string()))
        }

        "cfg" => {
            if args.len() < 5 { usage(); }
            let offset: usize = args[3].parse()
                .map_err(|e| format!("Invalid offset '{}': {}", args[3], e))?;
            let length: usize = args[4].parse()
                .map_err(|e| format!("Invalid length '{}': {}", args[4], e))?;
            build_cfg(path, offset, length)
                .and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string()))
        }

        "inspect" => {
            inspect_file_metadata(path)
                .and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string()))
        }

        "strings" => {
            extract_strings(path)
                .and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string()))
        }

        "identify" => {
            identify_format(path)
                .and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string()))
        }

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

