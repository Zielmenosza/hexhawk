//! Struct field inference via GEP (Get Element Pointer) instruction pattern analysis.
//!
//! Scans disassembly of a function (or a full .text section if no address given) for
//! register-relative memory accesses that look like struct field reads or writes:
//!   mov  eax, [rbx+0x10]   →  struct at rbx, field at offset 0x10
//!   lea  rax, [rdi+8]      →  struct at rdi, field at offset 8
//!
//! Groups discovered offsets by base register.  Each group becomes a candidate
//! `InferredStruct` whose fields are ordered by offset and annotated with an inferred
//! C primitive type based on the access size encoded in the mnemonic (byte/word/dword/qword).

use std::collections::{BTreeMap, HashMap};
use serde::{Deserialize, Serialize};
use crate::commands::disassemble::{capstone_for_arch, DisassembledInstruction};
use object::{Architecture, File as ObjectFile, Object, ObjectSection};
use memmap2::MmapOptions;
use std::fs;
use regex::Regex;

// ─── Public API types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredField {
    pub offset: i64,
    pub size_bytes: u32,
    pub inferred_type: String,
    pub access_count: u32,
    pub is_write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredStruct {
    pub base_register: String,
    pub fields: Vec<InferredField>,
    pub probable_size: u64,
    pub field_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferStructsResult {
    pub structs: Vec<InferredStruct>,
    pub instructions_scanned: usize,
    pub gep_patterns_found: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InferStructsRequest {
    pub binary_path: String,
    /// If provided, analyse only the function starting at this virtual address.
    /// If None, scan the entire .text section.
    pub function_address: Option<u64>,
    /// Maximum number of instructions to scan (default: 4096).
    pub max_instructions: Option<usize>,
    /// Minimum number of accesses to a base register before it is reported (default: 2).
    pub min_access_count: Option<u32>,
}

// ─── Tauri command ───────────────────────────────────────────────────────────

#[tauri::command]
pub fn infer_structs(request: InferStructsRequest) -> Result<InferStructsResult, String> {
    let file = fs::File::open(&request.binary_path)
        .map_err(|e| format!("Cannot open file: {e}"))?;
    let mmap = unsafe { MmapOptions::new().map(&file) }
        .map_err(|e| format!("Cannot mmap file: {e}"))?;
    let data: &[u8] = &mmap;

    let obj = ObjectFile::parse(data).map_err(|e| format!("Cannot parse binary: {e}"))?;
    let arch = obj.architecture();
    let (cs, _arch_name, _fallback) = capstone_for_arch(arch, data)?;

    let max_insn = request.max_instructions.unwrap_or(4096);
    let min_accesses = request.min_access_count.unwrap_or(2);
    let mut warnings: Vec<String> = Vec::new();

    // Determine the byte range to scan.
    let scan_bytes: &[u8] = if let Some(func_addr) = request.function_address {
        // Find the section that contains this VA and slice from func_addr.
        let section = obj
            .sections()
            .find(|s| {
                let start = s.address();
                let end = start + s.size();
                func_addr >= start && func_addr < end
            })
            .ok_or_else(|| format!("No section contains address 0x{func_addr:x}"))?;
        let raw = section.data().map_err(|e| format!("Cannot read section data: {e}"))?;
        let offset = (func_addr - section.address()) as usize;
        if offset >= raw.len() {
            return Err(format!("Offset 0x{offset:x} exceeds section size"));
        }
        &raw[offset..]
    } else {
        // Scan the first executable section (.text or flags-based).
        let section = obj
            .sections()
            .find(|s| {
                let name = s.name().unwrap_or("");
                name == ".text" || name == "CODE" || name == "__text"
            })
            .ok_or_else(|| ".text section not found".to_string())?;
        section.data().map_err(|e| format!("Cannot read .text: {e}"))?
    };

    // Disassemble up to max_insn instructions.
    let base_va: u64 = request.function_address.unwrap_or(0);
    let insns = cs
        .disasm_count(scan_bytes, base_va, max_insn)
        .map_err(|e| format!("Disassembly failed: {e}"))?;

    // Collect DisassembledInstruction-style tuples from the Capstone result.
    let raw_insns: Vec<DisassembledInstruction> = insns
        .iter()
        .map(|i| DisassembledInstruction {
            address: i.address(),
            mnemonic: i.mnemonic().unwrap_or("").to_string(),
            operands: i.op_str().unwrap_or("").to_string(),
            is_bad: false,
        })
        .collect();

    let instructions_scanned = raw_insns.len();

    // ── GEP pattern extraction ────────────────────────────────────────────────
    //
    // Pattern: `[REG ± OFFSET]` in the operand string.
    // Architectures targeted: x86, x86-64 (most common in reverse engineering).
    // ARM/AARCH64 patterns: `[REG, #OFFSET]`.
    //
    // We also track whether the memory side is dst (write) or src (read):
    //   dst written → first operand contains the bracket expression → write
    //   src read    → second operand contains the bracket expression → read

    let re_x86 = Regex::new(
        r"(?i)\[(?P<reg>[a-z][a-z0-9]*)(?:\s*(?P<sign>[+\-])\s*(?:0x)?(?P<off>[0-9a-f]+))?\]"
    ).expect("static regex");
    let re_arm = Regex::new(
        r"(?i)\[(?P<reg>[a-z][a-z0-9]*)(?:,\s*#(?P<sign>-)?(?:0x)?(?P<off>[0-9a-f]+))?\]"
    ).expect("static regex");

    // Per base register, map offset → (size, access_count, is_write_count).
    // Key = (base_reg, offset), value = (size_bytes, total_count, write_count)
    let mut access_map: HashMap<(String, i64), (u32, u32, u32)> = HashMap::new();
    let mut gep_patterns_found = 0usize;

    for insn in &raw_insns {
        let mnemonic = insn.mnemonic.to_lowercase();
        let size_bytes = mnemonic_to_size(&mnemonic, arch);

        // Skip non-memory mnemonics entirely for efficiency.
        if !is_memory_mnemonic(&mnemonic) {
            continue;
        }

        let operands = &insn.operands;
        // Split at first comma to tell dst from src (x86 convention).
        let comma_pos = operands.find(',').unwrap_or(operands.len());
        let dst = &operands[..comma_pos];
        let src = &operands[comma_pos..];

        for (part, is_write) in &[(dst, true), (src, false)] {
            let caps = re_x86.captures(part).or_else(|| re_arm.captures(part));
            if let Some(c) = caps {
                let reg = c.name("reg").map(|m| m.as_str().to_lowercase()).unwrap_or_default();
                // Filter noise: skip stack-pointer and instruction-pointer relative accesses.
                if matches!(reg.as_str(), "rsp" | "esp" | "sp" | "rip" | "eip" | "ip" | "pc") {
                    continue;
                }
                let sign: i64 = c.name("sign").map(|m| if m.as_str() == "-" { -1 } else { 1 }).unwrap_or(1);
                let off: i64 = c.name("off")
                    .and_then(|m| i64::from_str_radix(m.as_str(), 16).ok())
                    .unwrap_or(0);
                let offset = sign * off;
                // Ignore zero-offset accesses — too common/generic.
                if offset == 0 {
                    continue;
                }

                let key = (reg, offset);
                let entry = access_map.entry(key).or_insert((size_bytes, 0, 0));
                // Keep the largest observed size for the field.
                entry.0 = entry.0.max(size_bytes);
                entry.1 += 1;
                if *is_write { entry.2 += 1; }
                gep_patterns_found += 1;
            }
        }
    }

    if gep_patterns_found == 0 {
        warnings.push("No GEP-style memory access patterns detected in the scanned range. Try a larger range or a different function address.".to_string());
    }

    // ── Group by base register, apply min_access_count filter ────────────────

    // reg → BTreeMap<offset, (size, total, writes)>
    let mut by_reg: HashMap<String, BTreeMap<i64, (u32, u32, u32)>> = HashMap::new();
    for ((reg, off), (size, count, writes)) in access_map {
        if count >= min_accesses {
            by_reg.entry(reg).or_default().insert(off, (size, count, writes));
        }
    }

    // ── Build InferredStruct list ─────────────────────────────────────────────

    let mut structs: Vec<InferredStruct> = by_reg
        .into_iter()
        .filter(|(_, fields)| !fields.is_empty())
        .map(|(reg, fields)| {
            let field_vec: Vec<InferredField> = fields
                .iter()
                .map(|(&offset, &(size, count, writes))| {
                    InferredField {
                        offset,
                        size_bytes: size,
                        inferred_type: infer_c_type(size),
                        access_count: count,
                        is_write: writes > 0,
                    }
                })
                .collect();

            // Probable total size = max_offset + size of that field, rounded up.
            let probable_size = fields
                .iter()
                .map(|(&off, &(size, _, _))| (off.max(0) as u64).saturating_add(size as u64))
                .max()
                .unwrap_or(0);

            let field_count = field_vec.len();
            InferredStruct {
                base_register: reg,
                fields: field_vec,
                probable_size,
                field_count,
            }
        })
        .collect();

    // Sort structs by field_count descending (richer structs first).
    structs.sort_by(|a, b| b.field_count.cmp(&a.field_count));

    Ok(InferStructsResult {
        structs,
        instructions_scanned,
        gep_patterns_found,
        warnings,
    })
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Returns whether a mnemonic can encode a memory access.
fn is_memory_mnemonic(m: &str) -> bool {
    matches!(
        m,
        "mov" | "movsx" | "movsxd" | "movzx" | "movaps" | "movups"
        | "movdqu" | "movdqa" | "vmovdqu" | "vmovdqa"
        | "lea"
        | "add" | "sub" | "and" | "or" | "xor" | "cmp" | "test"
        | "push" | "pop"
        | "ldr" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrd"
        | "str" | "strb" | "strh" | "strd"
        | "ld1" | "st1"
    )
}

/// Returns the data size in bytes implied by an x86/ARM mnemonic.
fn mnemonic_to_size(m: &str, arch: Architecture) -> u32 {
    // ARM
    if matches!(
        arch,
        Architecture::Aarch64 | Architecture::Arm
    ) {
        return match m {
            "ldrb" | "strb" | "ldrsb" => 1,
            "ldrh" | "strh" | "ldrsh" => 2,
            "ldrd" | "strd" => 8,
            _ => 4, // ldr/str default to 4
        };
    }
    // x86
    if m.contains("byte") { return 1; }
    if m.contains("word") && !m.contains("dword") && !m.contains("qword") { return 2; }
    if m.contains("dword") { return 4; }
    if m.contains("qword") { return 8; }
    if m.contains("xmm") || m.contains("ymm") || m.contains("dqu") || m.contains("dqa") { return 16; }
    // Heuristic for plain mov/add/etc. based on register width hints:
    4
}

/// Maps a byte size to an approximate C primitive type.
fn infer_c_type(size: u32) -> String {
    match size {
        1 => "uint8_t".to_string(),
        2 => "uint16_t".to_string(),
        4 => "uint32_t".to_string(),
        8 => "uint64_t".to_string(),
        16 => "__m128i".to_string(),
        _ => format!("uint8_t[{}]", size),
    }
}
