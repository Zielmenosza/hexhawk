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

// plugins mod is required transitively by the commands (for tauri command macros);
// provide a minimal stub so it compiles as a standalone binary.
mod plugins {}

use cmd_disassemble::disassemble_file_range;
use cmd_graph::build_cfg;
use cmd_inspect::inspect_file_metadata;

fn usage() -> ! {
    eprintln!("Usage:");
    eprintln!("  nest_cli disassemble <path> <offset> <length>");
    eprintln!("  nest_cli cfg         <path> <offset> <length>");
    eprintln!("  nest_cli inspect     <path>");
    std::process::exit(1);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

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
            disassemble_file_range(path, offset, length)
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
