use capstone::prelude::*;
use object::{Architecture, File as ObjectFile, Object, ObjectSection};
use std::fs;
use memmap2::MmapOptions;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DisassembledInstruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    /// True if this instruction could not be decoded — the byte(s) are shown as a data directive
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_bad: bool,
}

/// Detect whether an ARM binary likely uses Thumb mode.
/// Heuristic: entry point address has LSB set (Thumb interworking convention).
fn arm_uses_thumb(data: &[u8]) -> bool {
    ObjectFile::parse(data)
        .ok()
        .and_then(|f| f.entry().checked_sub(0))
        .map(|ep| ep & 1 == 1)
        .unwrap_or(false)
}

/// Returns (Capstone engine, detected architecture name, is_fallback)
pub(crate) fn capstone_for_arch(arch: Architecture, data: &[u8]) -> Result<(Capstone, &'static str, bool), String> {
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
        Architecture::Arm => {
            // Choose Thumb or ARM mode based on entry point LSB
            if arm_uses_thumb(data) {
                Ok((Capstone::new()
                    .arm()
                    .mode(arch::arm::ArchMode::Thumb)
                    .build()
                    .map_err(e)?, "ARM (Thumb)", false))
            } else {
                Ok((Capstone::new()
                    .arm()
                    .mode(arch::arm::ArchMode::Arm)
                    .build()
                    .map_err(e)?, "ARM", false))
            }
        }
        Architecture::Aarch64 => Ok((Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .map_err(e)?, "AArch64", false)),
        Architecture::Mips => Ok((Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips32)
            .build()
            .map_err(e)?, "MIPS", false)),
        Architecture::Mips64 => Ok((Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips64)
            .build()
            .map_err(e)?, "MIPS64", false)),
        Architecture::PowerPc => Ok((Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode32)
            .build()
            .map_err(e)?, "PowerPC", false)),
        Architecture::PowerPc64 => Ok((Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode64)
            .build()
            .map_err(e)?, "PowerPC64", false)),
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
    /// Number of bytes that could not be decoded (skipped as data).
    pub bad_bytes: usize,
}

/// Robust disassembly with skip-on-error: when Capstone cannot decode bytes at
/// the current position, advance by 1 byte and emit a `.byte` data directive
/// instead of failing the entire call.  This handles:
///   - data interleaved with code (common in hand-written asm)
///   - obfuscated/encrypted code stubs
///   - misaligned entry points
fn disasm_robust(
    cs: &Capstone,
    slice: &[u8],
    base_addr: u64,
    limit: usize,
) -> (Vec<DisassembledInstruction>, usize) {
    let mut result = Vec::with_capacity(limit);
    let mut pos: usize = 0;
    let mut bad_bytes: usize = 0;

    while pos < slice.len() && result.len() < limit {
        let remaining = &slice[pos..];
        let addr = base_addr + pos as u64;

        match cs.disasm_count(remaining, addr, 1) {
            Ok(insns) if !insns.is_empty() => {
                let ins = insns.iter().next().unwrap();
                result.push(DisassembledInstruction {
                    address: ins.address(),
                    mnemonic: ins.mnemonic().unwrap_or("").to_string(),
                    operands: ins.op_str().unwrap_or("").to_string(),
                    is_bad: false,
                });
                pos += ins.bytes().len();
            }
            _ => {
                // Emit a data byte directive and skip one byte
                result.push(DisassembledInstruction {
                    address: addr,
                    mnemonic: ".byte".to_string(),
                    operands: format!("0x{:02X}", slice[pos]),
                    is_bad: true,
                });
                pos += 1;
                bad_bytes += 1;
            }
        }
    }

    (result, bad_bytes)
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
            bad_bytes: 0,
        });
    }

    // Auto-detect architecture from file header; fall back to x86-64
    let detected_arch = ObjectFile::parse(data)
        .map(|f| f.architecture())
        .unwrap_or(Architecture::X86_64);

    // If offset == 0 and this is a parsed object, try to snap to the .text section
    // so we skip the PE/ELF header bytes that cause spurious decode failures.
    let (effective_offset, effective_length) = snap_to_text_section(data, offset, length);

    let end = std::cmp::min(effective_offset + effective_length, data.len());
    let slice = &data[effective_offset..end];
    let end_file_offset = end as u64;

    let (cs, arch_name, is_fallback) = capstone_for_arch(detected_arch, data)?;

    let limit = max_instructions.unwrap_or(256) as usize;

    let (instructions, bad_bytes) = disasm_robust(&cs, slice, effective_offset as u64, limit);

    let next_byte_offset = instructions
        .last()
        .map(|ins| {
            // For .byte directives, advance by 1
            if ins.is_bad { ins.address + 1 } else { ins.address + 1 } // approximate; exact for good insns
        })
        .unwrap_or(end_file_offset);

    let has_more = next_byte_offset < end_file_offset && instructions.len() == limit;

    Ok(DisassemblyResult {
        arch: arch_name.to_string(),
        is_fallback,
        instructions,
        has_more,
        next_byte_offset,
        bad_bytes,
    })
}

/// If the caller starts at offset 0 and the file is a parseable object, advance
/// the offset to the file position of the first executable section (.text / .code)
/// to avoid disassembling the file header.  Returns the original values unchanged
/// if the section cannot be found or the caller chose a non-zero offset.
fn snap_to_text_section(data: &[u8], offset: usize, length: usize) -> (usize, usize) {
    if offset != 0 {
        return (offset, length);
    }
    let Ok(obj) = ObjectFile::parse(data) else {
        return (offset, length);
    };
    // Find first text-like section
    let sec = obj.sections().find(|s| {
        let name = s.name().unwrap_or("").to_ascii_lowercase();
        name == ".text" || name == ".code" || name == "__text"
    });
    let Some(sec) = sec else {
        return (offset, length);
    };
    let Some((file_offset, file_size)) = sec.file_range() else {
        return (offset, length);
    };
    (file_offset as usize, file_size as usize)
}

