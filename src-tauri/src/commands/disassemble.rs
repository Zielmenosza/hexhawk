use capstone::prelude::*;
use object::{Architecture, File as ObjectFile, Object};
use std::fs;
use memmap2::MmapOptions;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DisassembledInstruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
}

/// Returns (Capstone engine, detected architecture name, is_fallback)
fn capstone_for_arch(arch: Architecture) -> Result<(Capstone, &'static str, bool), String> {
    let e = |err: capstone::Error| format!("Failed to initialize Capstone: {}", err);
    match arch {
        Architecture::I386 => Ok((Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .build()
            .map_err(e)?, "x86", false)),
        Architecture::X86_64 => Ok((Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build()
            .map_err(e)?, "x86-64", false)),
        Architecture::Arm => Ok((Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .build()
            .map_err(e)?, "ARM", false)),
        Architecture::Aarch64 => Ok((Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .map_err(e)?, "AArch64", false)),
        // Unsupported: fall back to x86-64, mark as fallback so caller can warn
        _ => Ok((Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build()
            .map_err(e)?, "x86-64 (fallback — architecture not supported)", true)),
    }
}

#[derive(Debug, serde::Serialize)]
pub struct DisassemblyResult {
    pub arch: String,
    pub is_fallback: bool,
    pub instructions: Vec<DisassembledInstruction>,
    /// True when more instructions exist beyond the returned chunk.
    pub has_more: bool,
    /// File byte offset to pass as `offset` for the next chunk (0 when `has_more` is false).
    pub next_byte_offset: u64,
}

#[tauri::command]
pub fn disassemble_file_range(
    path: String,
    offset: usize,
    length: usize,
    // Maximum number of instructions to return per call. Defaults to 256 when None.
    max_instructions: Option<u64>,
) -> Result<DisassemblyResult, String> {
    // Memory-map the file — no size limit, OS handles paging
    let file_handle = fs::File::open(&path)
        .map_err(|e| format!("Failed to open file: {e}"))?;
    let mmap = unsafe {
        MmapOptions::new().map(&file_handle)
            .map_err(|e| format!("Failed to mmap file: {e}"))?
    };
    let data: &[u8] = &mmap;

    if offset >= data.len() {
        return Ok(DisassemblyResult {
            arch: "unknown".into(),
            is_fallback: false,
            instructions: vec![],
            has_more: false,
            next_byte_offset: 0,
        });
    }

    let end = std::cmp::min(offset + length, data.len());
    let slice = &data[offset..end];
    let end_file_offset = end as u64;

    // Auto-detect architecture from file header; fall back to x86-64
    let detected_arch = ObjectFile::parse(&*data)
        .map(|f| f.architecture())
        .unwrap_or(Architecture::X86_64);

    let (cs, arch_name, is_fallback) = capstone_for_arch(detected_arch)?;

    let limit = max_instructions.unwrap_or(256) as usize;

    // Disassemble up to `limit` instructions.  disasm_count is cheaper than
    // disasm_all because Capstone stops after reaching the requested count.
    let insns = cs
        .disasm_count(slice, offset as u64, limit)
        .map_err(|e| format!("Failed to disassemble: {}", e))?;

    // Determine the file byte offset immediately after the last returned instruction.
    // `ins.address()` equals `offset as u64 + local_offset_within_slice`, so it
    // already encodes the file position.
    let next_byte_offset = insns
        .iter()
        .last()
        .map(|ins| ins.address() + ins.bytes().len() as u64)
        .unwrap_or(end_file_offset);

    let has_more = next_byte_offset < end_file_offset;

    let result: Vec<DisassembledInstruction> = insns
        .iter()
        .map(|ins| DisassembledInstruction {
            address: ins.address(),
            mnemonic: ins.mnemonic().unwrap_or("").to_string(),
            operands: ins.op_str().unwrap_or("").to_string(),
        })
        .collect();

    Ok(DisassemblyResult {
        arch: arch_name.to_string(),
        is_fallback,
        instructions: result,
        has_more,
        next_byte_offset,
    })
}

