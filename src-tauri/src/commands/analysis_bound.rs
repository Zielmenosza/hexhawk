//! Native static-analysis boundary: hash and parse one owned 64 MiB-capped
//! snapshot. Legacy Rust helpers are not registered as IPC handlers.
use super::{disassemble, graph, hex, inspect, pe_imports};
use std::sync::atomic::{AtomicUsize, Ordering};

const MAX_ACTIVE_ANALYSES: usize = 4;
const RELEASE_INPUT_SCOPE: &str = "Windows first release requires a valid PE32/x86 or PE32+/x64 EXE/DLL input";

// Release qualification belongs to the checked IPC boundary, not the legacy
// multi-format Rust/CLI reader. Inspect the exact owned bytes before any checked
// operation can return evidence or select a decoder. Machine AND optional-header
// width must agree: object 0.31 reports architecture from Machine alone.
fn validate_release_input(data: &[u8]) -> Result<(), String> {
    let malformed = || format!("{RELEASE_INPUT_SCOPE}; malformed or unsupported image.");
    if !data.starts_with(b"MZ") || data.len() < 64 {
        return Err(malformed());
    }
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().map_err(|_| malformed())?) as usize;
    let end = pe.checked_add(24).ok_or_else(malformed)?;
    let header = data.get(pe..end).ok_or_else(malformed)?;
    if pe < 64 || &header[..4] != b"PE\0\0" {
        return Err(malformed());
    }
    let machine = u16::from_le_bytes([header[4], header[5]]);
    let opt_size = u16::from_le_bytes([header[20], header[21]]) as usize;
    let characteristics = u16::from_le_bytes([header[22], header[23]]);
    let opt_end = end.checked_add(opt_size).ok_or_else(malformed)?;
    let opt = data.get(end..opt_end).ok_or_else(malformed)?;
    let magic = opt.get(..2).ok_or_else(malformed)?;
    let magic = u16::from_le_bytes([magic[0], magic[1]]);
    if !matches!((machine, magic), (0x14c, 0x10b) | (0x8664, 0x20b))
        || characteristics & object::pe::IMAGE_FILE_EXECUTABLE_IMAGE == 0
        || opt_size < if magic == 0x20b { 112 } else { 96 }
    {
        return Err(malformed());
    }
    // Reuse the existing bounded PE structural parser: complete optional header,
    // directories and section table/raw extents, with the existing name budgets.
    // A matching magic/machine prefix alone must not unlock hex/string evidence.
    pe_imports::parse_pe_section_names(data)
        .map_err(|error| format!("{RELEASE_INPUT_SCOPE}; {error}"))?;
    Ok(())
}

static ACTIVE_ANALYSES: AtomicUsize = AtomicUsize::new(0);
struct AnalysisPermit;
impl Drop for AnalysisPermit {
    fn drop(&mut self) { ACTIVE_ANALYSES.fetch_sub(1, Ordering::AcqRel); }
}
pub(super) fn with_admission<T>(operation: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    ACTIVE_ANALYSES.fetch_update(Ordering::AcqRel, Ordering::Acquire, |active|
        (active < MAX_ACTIVE_ANALYSES).then_some(active + 1)
    ).map_err(|_| "Native analysis is busy (maximum four concurrent operations); retry after completion.".to_string())?;
    let _permit = AnalysisPermit;
    operation()
}
pub(super) fn with_identity<T>(path: &str, expected: &str, operation: impl FnOnce(&[u8]) -> Result<T, String>) -> Result<T, String> {
    with_admission(|| {
        let snapshot = inspect::read_identity_snapshot(path, expected)?;
        validate_release_input(&snapshot)?;
        operation(&snapshot)
    })
}

#[tauri::command]
pub fn inspect_file_metadata(path: String) -> Result<inspect::FileMetadata, String> {
    with_admission(|| {
        let snapshot = inspect::read_inspection_snapshot(&path)?;
        validate_release_input(&snapshot)?;
        inspect::metadata_snapshot(&snapshot)
    })
}

#[tauri::command]
pub fn inspect_pe_extras(path: String, expected_sha256: String) -> Result<inspect::PeExtras, String> {
    with_identity(&path, &expected_sha256, pe_imports::parse_pe_extras)
}

#[tauri::command]
pub fn inspect_macho_load_commands(path: String, expected_sha256: String) -> Result<Vec<inspect::MachLoadCommand>, String> {
    with_identity(&path, &expected_sha256, inspect::macho_commands_snapshot)
}

#[tauri::command]
pub fn read_hex_range(path: String, offset: u64, length: usize, expected_sha256: String) -> Result<Vec<u8>, String> {
    let requested = u64::try_from(length).map_err(|_| "Hex length cannot be represented")?;
    offset.checked_add(requested).ok_or("Hex range overflow")?;
    if length > hex::MAX_HEX_BYTES { return Err(format!("Hex byte budget exceeded (maximum {})",hex::MAX_HEX_BYTES)); }
    with_identity(&path, &expected_sha256, |data| {
        let start = usize::try_from(offset).map_err(|_| "Hex offset cannot be represented")?.min(data.len());
        let end = start.saturating_add(length).min(data.len());
        Ok(data[start..end].to_vec())
    })
}

#[tauri::command]
pub fn find_strings(path: String, offset: usize, length: usize, min_length: usize, expected_sha256: String) -> Result<Vec<hex::StringMatch>, String> {
    let end = offset.checked_add(length).ok_or("String scan range overflow")?;
    if length > hex::MAX_STRING_SCAN_BYTES { return Err(format!("String scan byte budget exceeded (maximum {})",hex::MAX_STRING_SCAN_BYTES)); }
    with_identity(&path, &expected_sha256, |data| {
        let start = offset.min(data.len());
        let end = end.min(data.len());
        hex::find_strings_in_bytes(&data[start..end], min_length, start as u64)
    })
}

#[tauri::command]
pub fn disassemble_file_range(path: String, offset: usize, length: usize, max_instructions: Option<u64>, expected_sha256: String) -> Result<disassemble::DisassemblyResult, String> {
    disassemble::validate_disassembly_request(offset, length, max_instructions)?;
    with_identity(&path, &expected_sha256, |data| disassemble::disassemble_snapshot(data, offset, length, max_instructions))
}

#[tauri::command]
pub fn build_cfg(path: String, offset: usize, length: usize, expected_sha256: String) -> Result<graph::CfgGraph, String> {
    graph::validate_cfg_request(offset, length)?;
    with_identity(&path, &expected_sha256, |data| graph::cfg_snapshot(data, offset, length))
}

#[cfg(test)]
pub(super) static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
