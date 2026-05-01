//! HexHawk Batch Script API
//!
//! Executes a sequence of named operations against a target file and returns
//! per-step results. Inspired by IDAPython but driven entirely by JSON over
//! Tauri IPC — any language/tool that can call `invoke('run_script', ...)` can
//! drive HexHawk programmatically.
//!
//! Operations available:
//!   disassemble   — disassemble a byte range
//!   disassemble_section — disassemble a named section (.text, .code, …)
//!   strings       — extract strings from a range
//!   hex           — read raw bytes as hex
//!   inspect       — file metadata / imports / exports / sections
//!   cfg           — build control-flow graph for an address
//!   patch_nop     — NOP out a byte range (in-memory, no disk write)
//!   xref_to       — find all call/jump sites that reference an address
//!   find_bytes    — byte-pattern search (yara-lite)
//!   entropy       — compute Shannon entropy over a range

use std::time::Instant;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commands::disassemble::disassemble_file_range;
use crate::commands::hex::{get_file_size, read_hex_range};
use crate::commands::strings::extract_strings;
use crate::commands::inspect::inspect_file_metadata;

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ScriptStep {
    /// Operation name (see module doc)
    pub op: String,
    /// Operation-specific parameters (optional fields per op)
    #[serde(default)]
    pub params: Value,
    /// Store this step's result under a named key for reference in later steps
    pub result_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BatchScript {
    /// Absolute path to the binary to analyse
    pub path: String,
    /// Ordered list of steps to execute
    pub steps: Vec<ScriptStep>,
    /// Hard cap on total wall-time in milliseconds (default 60 000)
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct StepResult {
    pub step: usize,
    pub op: String,
    pub result_key: Option<String>,
    pub success: bool,
    pub data: Option<Value>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct ScriptOutput {
    pub path: String,
    pub steps_run: usize,
    pub steps_ok: usize,
    pub steps_failed: usize,
    pub total_duration_ms: u64,
    pub results: Vec<StepResult>,
}

// ── Helper — extract a typed field from step params ───────────────────────────

fn param_str<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key)?.as_str()
}

fn param_u64(params: &Value, key: &str, default: u64) -> u64 {
    params.get(key)
        .and_then(|v| v.as_u64())
        .unwrap_or(default)
}

fn param_usize(params: &Value, key: &str, default: usize) -> usize {
    param_u64(params, key, default as u64) as usize
}

// ── Per-operation dispatch ────────────────────────────────────────────────────

pub(crate) fn run_step(path: &str, step: &ScriptStep) -> Result<Value, String> {
    match step.op.as_str() {
        // ── disassemble ───────────────────────────────────────────────────
        "disassemble" => {
            let offset   = param_usize(&step.params, "offset", 0);
            let length   = param_usize(&step.params, "length", 65536);
            let max_insn = step.params.get("max_instructions").and_then(|v| v.as_u64());
            let result   = disassemble_file_range(path.to_string(), offset, length, max_insn)?;
            serde_json::to_value(result).map_err(|e| e.to_string())
        }

        // ── disassemble_section ────────────────────────────────────────────
        "disassemble_section" => {
            let section_name = param_str(&step.params, "section")
                .unwrap_or(".text")
                .to_string();
            let max_insn = step.params.get("max_instructions").and_then(|v| v.as_u64());
            disassemble_section(path, &section_name, max_insn)
        }

        // ── strings ───────────────────────────────────────────────────────
        "strings" => {
            let result = extract_strings(path.to_string())?;
            serde_json::to_value(result).map_err(|e| e.to_string())
        }

        // ── hex ───────────────────────────────────────────────────────────
        "hex" => {
            let offset = param_u64(&step.params, "offset", 0);
            let length = param_usize(&step.params, "length", 256);
            let bytes  = read_hex_range(path.to_string(), offset, length)?;
            let hex_str: String = bytes.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            Ok(serde_json::json!({
                "offset": offset,
                "length": bytes.len(),
                "hex": hex_str,
                "bytes": bytes,
            }))
        }

        // ── inspect ───────────────────────────────────────────────────────
        "inspect" => {
            let result = inspect_file_metadata(path.to_string())
                .map_err(|e| format!("inspect failed: {e}"))?;
            serde_json::to_value(result).map_err(|e| e.to_string())
        }

        // ── file_size ─────────────────────────────────────────────────────
        "file_size" => {
            let size = get_file_size(path.to_string())?;
            Ok(serde_json::json!({ "bytes": size, "kb": size / 1024, "mb": size / 1048576 }))
        }

        // ── entropy ───────────────────────────────────────────────────────
        "entropy" => {
            let offset = param_u64(&step.params, "offset", 0);
            let length = param_usize(&step.params, "length", 65536);
            let bytes  = read_hex_range(path.to_string(), offset, length)?;
            let h      = shannon_entropy(&bytes);
            Ok(serde_json::json!({
                "offset": offset,
                "bytes_sampled": bytes.len(),
                "entropy": h,
                "interpretation": classify_entropy(h),
            }))
        }

        // ── find_bytes ────────────────────────────────────────────────────
        "find_bytes" => {
            let pattern_hex = step.params.get("pattern")
                .and_then(|v| v.as_str())
                .ok_or("find_bytes: 'pattern' (hex string) required")?;
            let limit = param_usize(&step.params, "limit", 256);
            find_byte_pattern(path, pattern_hex, limit)
        }

        // ── xref_to ───────────────────────────────────────────────────────
        "xref_to" => {
            let target_addr = step.params.get("address")
                .and_then(|v| v.as_u64())
                .ok_or("xref_to: 'address' (integer) required")?;
            let max_insn = param_usize(&step.params, "max_instructions", 8192);
            find_xrefs_to(path, target_addr, max_insn)
        }

        // ── section_map ───────────────────────────────────────────────────
        "section_map" => {
            list_sections(path)
        }

        unknown => Err(format!("Unknown operation: '{unknown}'. Valid ops: disassemble, disassemble_section, strings, hex, inspect, file_size, entropy, find_bytes, xref_to, section_map")),
    }
}

// ── Main Tauri command ────────────────────────────────────────────────────────

#[tauri::command]
pub fn run_script(script: BatchScript) -> Result<ScriptOutput, String> {
    if script.steps.is_empty() {
        return Err("Script contains no steps.".to_string());
    }
    if script.steps.len() > 256 {
        return Err("Script exceeds maximum of 256 steps.".to_string());
    }

    let path = &script.path;
    // Validate path exists before running any steps
    std::fs::metadata(path)
        .map_err(|_| format!("File not found: {path}"))?;

    let timeout_ms = script.timeout_ms.unwrap_or(60_000).min(300_000);
    let deadline   = Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let wall_start = Instant::now();

    let mut results: Vec<StepResult> = Vec::with_capacity(script.steps.len());
    let mut steps_ok = 0usize;
    let mut steps_failed = 0usize;

    for (i, step) in script.steps.iter().enumerate() {
        if Instant::now() >= deadline {
            results.push(StepResult {
                step: i,
                op: step.op.clone(),
                result_key: step.result_key.clone(),
                success: false,
                data: None,
                error: Some(format!("Script timeout ({timeout_ms} ms) exceeded before this step ran.")),
                duration_ms: 0,
            });
            steps_failed += 1;
            continue;
        }

        let t0 = Instant::now();
        let outcome = run_step(path, step);
        let duration_ms = t0.elapsed().as_millis() as u64;

        match outcome {
            Ok(data) => {
                steps_ok += 1;
                results.push(StepResult {
                    step: i,
                    op: step.op.clone(),
                    result_key: step.result_key.clone(),
                    success: true,
                    data: Some(data),
                    error: None,
                    duration_ms,
                });
            }
            Err(e) => {
                steps_failed += 1;
                results.push(StepResult {
                    step: i,
                    op: step.op.clone(),
                    result_key: step.result_key.clone(),
                    success: false,
                    data: None,
                    error: Some(e),
                    duration_ms,
                });
            }
        }
    }

    Ok(ScriptOutput {
        path: path.clone(),
        steps_run: results.len(),
        steps_ok,
        steps_failed,
        total_duration_ms: wall_start.elapsed().as_millis() as u64,
        results,
    })
}

// ── Operation implementations ─────────────────────────────────────────────────

fn disassemble_section(path: &str, section_name: &str, max_insn: Option<u64>) -> Result<Value, String> {
    use object::{Object, ObjectSection};
    use std::fs;
    use memmap2::MmapOptions;

    let file_handle = fs::File::open(path)
        .map_err(|e| format!("Cannot open file: {e}"))?;
    let mmap = unsafe {
        MmapOptions::new().map(&file_handle)
            .map_err(|e| format!("mmap failed: {e}"))?
    };

    let obj = object::File::parse(&*mmap)
        .map_err(|e| format!("Object parse failed: {e}"))?;

    // Find the section by name (try both with and without dot prefix)
    let sec = obj.sections()
        .find(|s| {
            let name = s.name().unwrap_or("");
            name.eq_ignore_ascii_case(section_name)
                || name.eq_ignore_ascii_case(&format!(".{}", section_name.trim_start_matches('.')))
        })
        .ok_or_else(|| {
            let names: Vec<_> = obj.sections()
                .filter_map(|s| s.name().ok().map(|n| n.to_string()))
                .collect();
            format!("Section '{section_name}' not found. Available: {}", names.join(", "))
        })?;

    let file_offset = sec.file_range()
        .ok_or_else(|| format!("Section '{section_name}' has no file range (BSS?)"))?
        .0 as usize;
    let sec_size = sec.size() as usize;

    let result = disassemble_file_range(
        path.to_string(),
        file_offset,
        sec_size,
        max_insn,
    )?;

    let mut v = serde_json::to_value(result).map_err(|e| e.to_string())?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("section".to_string(), Value::String(section_name.to_string()));
        obj.insert("section_offset".to_string(), Value::Number(file_offset.into()));
        obj.insert("section_size".to_string(), Value::Number(sec_size.into()));
    }
    Ok(v)
}

fn list_sections(path: &str) -> Result<Value, String> {
    use object::{Object, ObjectSection, SectionKind};
    use std::fs;
    use memmap2::MmapOptions;

    let file_handle = fs::File::open(path)
        .map_err(|e| format!("Cannot open file: {e}"))?;
    let mmap = unsafe {
        MmapOptions::new().map(&file_handle)
            .map_err(|e| format!("mmap failed: {e}"))?
    };

    let obj = object::File::parse(&*mmap)
        .map_err(|e| format!("Object parse failed: {e}"))?;

    let sections: Vec<Value> = obj.sections().map(|sec| {
        let kind = match sec.kind() {
            SectionKind::Text => "text",
            SectionKind::Data => "data",
            SectionKind::ReadOnlyData => "rodata",
            SectionKind::UninitializedData => "bss",
            SectionKind::Other => "other",
            _ => "unknown",
        };
        let (file_offset, file_size) = sec.file_range().unwrap_or((0, 0));
        serde_json::json!({
            "name": sec.name().unwrap_or("?"),
            "kind": kind,
            "virtual_address": sec.address(),
            "file_offset": file_offset,
            "size": sec.size(),
            "file_size": file_size,
        })
    }).collect();

    Ok(serde_json::json!({ "sections": sections, "count": sections.len() }))
}

fn find_byte_pattern(path: &str, pattern_hex: &str, limit: usize) -> Result<Value, String> {
    use std::fs;
    use memmap2::MmapOptions;

    // Parse hex pattern, allowing spaces and wildcards ('??')
    let tokens: Vec<&str> = pattern_hex.split_whitespace().collect();
    if tokens.is_empty() {
        return Err("find_bytes: pattern is empty".to_string());
    }
    if tokens.len() > 256 {
        return Err("find_bytes: pattern too long (max 256 bytes)".to_string());
    }

    // Each token is either a hex byte "AB" or a wildcard "??"
    let pattern: Vec<Option<u8>> = tokens.iter().map(|t| {
        if *t == "??" || *t == "?" {
            None
        } else {
            u8::from_str_radix(t, 16).ok()
        }
    }).collect();

    let file_handle = fs::File::open(path)
        .map_err(|e| format!("Cannot open file: {e}"))?;
    let mmap = unsafe {
        MmapOptions::new().map(&file_handle)
            .map_err(|e| format!("mmap failed: {e}"))?
    };
    let data: &[u8] = &mmap;

    let pat_len = pattern.len();
    let mut matches: Vec<Value> = Vec::new();

    'outer: for i in 0..data.len().saturating_sub(pat_len - 1) {
        for (j, pat_byte) in pattern.iter().enumerate() {
            if let Some(expected) = pat_byte {
                if data[i + j] != *expected {
                    continue 'outer;
                }
            }
        }
        let matched_hex: String = data[i..i + pat_len]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        matches.push(serde_json::json!({
            "offset": i,
            "hex": matched_hex,
        }));
        if matches.len() >= limit {
            break;
        }
    }

    Ok(serde_json::json!({
        "pattern": pattern_hex,
        "matches": matches,
        "count": matches.len(),
        "truncated": matches.len() >= limit,
    }))
}

fn find_xrefs_to(path: &str, target_addr: u64, max_insn: usize) -> Result<Value, String> {
    use capstone::prelude::*;
    use object::{Architecture, Object};
    use std::fs;
    use memmap2::MmapOptions;

    let file_handle = fs::File::open(path)
        .map_err(|e| format!("Cannot open file: {e}"))?;
    let mmap = unsafe {
        MmapOptions::new().map(&file_handle)
            .map_err(|e| format!("mmap failed: {e}"))?
    };
    let data: &[u8] = &mmap;

    let obj = object::File::parse(data)
        .map_err(|e| format!("Object parse failed: {e}"))?;

    let cs = match obj.architecture() {
        Architecture::X86_64 => Capstone::new().x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .map_err(|e| e.to_string())?,
        Architecture::I386 => Capstone::new().x86()
            .mode(arch::x86::ArchMode::Mode32)
            .detail(true)
            .build()
            .map_err(|e| e.to_string())?,
        Architecture::Aarch64 => Capstone::new().arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|e| e.to_string())?,
        _ => Capstone::new().x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .map_err(|e| e.to_string())?,
    };

    let limit = max_insn.min(65536);
    let insns = cs.disasm_count(data, 0, limit)
        .map_err(|e| format!("Disassembly failed: {e}"))?;

    let mut xrefs: Vec<Value> = Vec::new();
    for ins in insns.iter() {
        let m = ins.mnemonic().unwrap_or("");
        let ops = ins.op_str().unwrap_or("");
        // Check if operand resolves to target address
        // Simple: look for the target address hex in the operand string
        let target_hex_lo = format!("{:x}", target_addr);
        let target_hex_up = format!("{:X}", target_addr);
        let target_dec    = format!("{}", target_addr);
        if ops.contains(&target_hex_lo) || ops.contains(&target_hex_up) || ops.contains(&target_dec) {
            let kind = if m.starts_with('j') || m == "jmp" {
                "jump"
            } else if m == "call" || m == "callq" {
                "call"
            } else {
                "data"
            };
            xrefs.push(serde_json::json!({
                "from": ins.address(),
                "mnemonic": m,
                "operands": ops,
                "kind": kind,
            }));
        }
    }

    Ok(serde_json::json!({
        "target": target_addr,
        "xrefs": xrefs,
        "count": xrefs.len(),
    }))
}

pub(crate) fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub(crate) fn classify_entropy(h: f64) -> &'static str {
    match h as u32 {
        0..=3 => "low (plaintext / structured data)",
        4..=5 => "moderate (mixed code/data)",
        6..=7 => "high (compressed or encrypted likely)",
        _     => "very high (likely encrypted / packed)",
    }
}
