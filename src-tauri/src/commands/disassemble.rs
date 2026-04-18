use capstone::prelude::*;
use object::{Architecture, File as ObjectFile, Object};
use std::fs;

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
}

#[tauri::command]
pub fn disassemble_file_range(
    path: String,
    offset: usize,
    length: usize,
) -> Result<DisassemblyResult, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;

    if offset >= data.len() {
        return Ok(DisassemblyResult { arch: "unknown".into(), is_fallback: false, instructions: vec![] });
    }

    let end = std::cmp::min(offset + length, data.len());
    let slice = &data[offset..end];

    // Auto-detect architecture from file header; fall back to x86-64
    let detected_arch = ObjectFile::parse(&*data)
        .map(|f| f.architecture())
        .unwrap_or(Architecture::X86_64);

    let (cs, arch_name, is_fallback) = capstone_for_arch(detected_arch)?;

    let instructions = cs
        .disasm_all(slice, offset as u64)
        .map_err(|e| format!("Failed to disassemble: {}", e))?;

    let result = instructions
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
    })
}

