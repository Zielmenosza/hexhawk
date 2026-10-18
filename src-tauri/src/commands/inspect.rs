use super::pe_imports::{parse_pe_exports, parse_pe_extras, parse_pe_imports, parse_pe_section_names, PeImportEntry};
pub use super::pe_imports::PeExtras;
use md5::Md5;

use object::{Architecture, File, Object, ObjectSection};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;

const MAX_INSPECTION_BYTES: u64 = 64 * 1024 * 1024;

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::shannon_entropy;
    use super::{compute_hashes, inspect_file_metadata};
    use std::fs;
    use std::io::Write;

    #[test]
    fn inspection_rejects_over_budget_input_before_identity_is_returned() {
        let path = std::env::temp_dir().join(format!("hexhawk-inspect-budget-{}.bin", std::process::id()));
        let file = fs::File::create(&path).expect("create inert sparse input");
        file.set_len(64 * 1024 * 1024 + 1).expect("set inert size");
        drop(file);
        let result = inspect_file_metadata(path.to_string_lossy().into_owned());
        fs::remove_file(path).expect("remove inert input");
        assert!(result.is_err(), "over-budget inspection must not return a misleading identity");
    }

    #[test]
    fn hashing_rejects_a_short_read_instead_of_returning_a_digest() {
        let path = std::env::temp_dir().join(format!("hexhawk-inspect-short-{}.bin", std::process::id()));
        let mut file = fs::File::create(&path).expect("create inert input");
        file.write_all(b"abc").expect("write inert input");
        drop(file);
        let result = compute_hashes(&fs::read(&path).expect("read inert input"), 4);
        fs::remove_file(path).expect("remove inert input");
        assert!(result.is_err(), "a short read must not earn whole-file identity");
    }

    #[test]
    fn malformed_mz_input_is_not_reported_as_successful_binary_inspection() {
        let path = std::env::temp_dir().join(format!("hexhawk-inspect-mz-{}.bin", std::process::id()));
        fs::write(&path, b"MZnot-a-valid-PE").expect("write inert malformed input");
        let result = inspect_file_metadata(path.to_string_lossy().into_owned());
        fs::remove_file(path).expect("remove inert input");
        assert!(result.is_err(), "malformed PE must not become a nominal successful inspection");
    }

    #[test]
    fn entropy_of_empty_bytes_is_zero() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn entropy_of_uniform_bytes_is_zero() {
        // All identical bytes → entropy = 0 (only one symbol)
        let data = vec![0x41u8; 256];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn entropy_of_maximally_random_bytes_is_near_eight() {
        // All 256 byte values each appearing once → entropy = 8.0
        let data: Vec<u8> = (0u8..=255).collect();
        let h = shannon_entropy(&data);
        assert!((h - 8.0).abs() < 0.001, "Expected ~8.0, got {h}");
    }

    #[test]
    fn entropy_of_two_symbols_is_one() {
        // Equal mix of two byte values → H = 1.0
        let data: Vec<u8> = (0..256).map(|i| if i % 2 == 0 { 0 } else { 1 }).collect();
        let h = shannon_entropy(&data);
        assert!((h - 1.0).abs() < 0.001, "Expected 1.0, got {h}");
    }

    #[test]
    fn entropy_is_between_zero_and_eight() {
        let data: Vec<u8> = (0u8..128).collect();
        let h = shannon_entropy(&data);
        assert!(h >= 0.0 && h <= 8.0);
    }

    #[test]
    fn entropy_single_byte_is_zero() {
        assert_eq!(shannon_entropy(&[0xAA]), 0.0);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportEntry {
    pub name: String,
    pub library: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportEntry {
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionMetadata {
    pub name: String,
    pub file_offset: u64,
    pub file_size: u64,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub permissions: String,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginMetadata {
    pub name: String,
    pub description: String,
    pub version: Option<String>,
    pub enabled: bool,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileMetadata {
    pub file_type: String,
    pub architecture: String,
    pub entry_point: u64,
    pub file_size: u64,
    pub image_base: u64,
    pub sections: Vec<SectionMetadata>,
    pub imports_count: usize,
    pub exports_count: usize,
    pub symbols_count: usize,
    pub imports: Vec<ImportEntry>,
    /// Advisory PE import table entries with IAT thunk virtual addresses. Empty for non-PE or parse failures.
    pub pe_imports: Vec<PeImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

// Hash and parse the same bounded, owned byte snapshot. A prefix digest must
// never be presented as whole-file identity, even for a large or changing file.
fn compute_hashes(data: &[u8], file_size: u64) -> Result<(String, String, String), String> {
    if data.len() as u64 != file_size {
        return Err("File changed or was truncated while reading; inspect it again.".into());
    }
    Ok((
        format!("{:x}", Sha256::digest(data)),
        format!("{:x}", sha1::Sha1::digest(data)),
        format!("{:x}", Md5::digest(data)),
    ))
}

pub(super) fn read_inspection_snapshot(path: &str) -> Result<Vec<u8>, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("Failed to open file: {e}"))?;
    let before = file.metadata().map_err(|e| format!("Failed to stat file: {e}"))?;
    if !before.is_file() {
        return Err("Inspection requires a regular file.".into());
    }
    if before.len() > MAX_INSPECTION_BYTES {
        return Err("File exceeds the 64 MiB static-inspection limit; no identity was returned.".into());
    }
    let mut data = Vec::new();
    Read::by_ref(&mut file).take(MAX_INSPECTION_BYTES + 1)
        .read_to_end(&mut data).map_err(|e| format!("Read error: {e}"))?;
    let after = file.metadata().map_err(|e| format!("Failed to restat file: {e}"))?;
    if data.len() as u64 > MAX_INSPECTION_BYTES || data.len() as u64 != before.len()
        || before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err("File changed or exceeded the inspection limit while reading; inspect it again.".into());
    }
    Ok(data)
}

/// Check the exact owned bytes the operation will parse, not a later path hash.
pub(super) fn read_identity_snapshot(path: &str, expected: &str) -> Result<Vec<u8>, String> {
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("A complete inspected SHA-256 is required; inspect the file first.".into());
    }
    let data = read_inspection_snapshot(path)?;
    let actual = format!("{:x}", Sha256::digest(&data));
    if !actual.eq_ignore_ascii_case(expected) {
        return Err("File identity changed since inspection; inspect the file again before analysis.".into());
    }
    Ok(data)
}

// ── Sampled entropy (avoids scanning full section for giant sections) ─────────
fn shannon_entropy_sampled(bytes: &[u8]) -> f64 {
    const MAX_SAMPLE: usize = 1024 * 1024; // 1 MB sample
    if bytes.len() <= MAX_SAMPLE {
        return shannon_entropy(bytes);
    }
    let half = MAX_SAMPLE / 2;
    let head = &bytes[..half];
    let tail = &bytes[bytes.len() - half..];
    let combined: Vec<u8> = head.iter().chain(tail.iter()).copied().collect();
    shannon_entropy(&combined)
}

// ── File magic / format detection ─────────────────────────────────────────────
fn detect_magic(data: &[u8]) -> (&'static str, &'static str) {
    match data {
        [0x4D, 0x5A, ..] => ("PE/MZ", "x86 or x64"),
        [0x7F, 0x45, 0x4C, 0x46, ..] => ("ELF", "see ELF header"),
        [0xCF, 0xFA, 0xED, 0xFE, ..] => ("Mach-O 64", "x64 or ARM64"),
        [0xCE, 0xFA, 0xED, 0xFE, ..] => ("Mach-O 32", "x86 or ARM"),
        [0xCA, 0xFE, 0xBA, 0xBE, ..] => ("Mach-O fat", "multi-arch"),
        [0x25, 0x50, 0x44, 0x46, ..] => ("PDF", "N/A"),
        [0x50, 0x4B, 0x03, 0x04, ..] | [0x50, 0x4B, 0x05, 0x06, ..] => ("ZIP/PKZIP", "N/A"),
        [0x52, 0x61, 0x72, 0x21, 0x1A, ..] => ("RAR", "N/A"),
        [0x37, 0x7A, 0xBC, 0xAF, 0x27, ..] => ("7-Zip", "N/A"),
        [0x1F, 0x8B, ..] => ("GZip", "N/A"),
        [0x42, 0x5A, 0x68, ..] => ("BZip2", "N/A"),
        [0x23, 0x21, ..] => ("Script", "N/A"),
        [0x0A, 0x0D, 0x0D, 0x0A, ..] => ("PCAPNG", "N/A"),
        [0xD4, 0xC3, 0xB2, 0xA1, ..] | [0xA1, 0xB2, 0xC3, 0xD4, ..] => ("PCAP", "N/A"),
        _ => ("Unknown", "unknown"),
    }
}

fn elf_arch(data: &[u8]) -> String {
    if data.len() < 20 {
        return "ELF".to_string();
    }
    let class = data[4]; // 1=32-bit, 2=64-bit
    let machine = if class == 2 {
        u16::from_le_bytes([data[18], data[19]])
    } else {
        data[18] as u16
    };
    match machine {
        3 => "x86".to_string(),
        62 => "x64".to_string(),
        40 => "ARM".to_string(),
        183 => "AArch64".to_string(),
        8 => "MIPS".to_string(),
        20 => "PowerPC".to_string(),
        n => format!("ELF (machine=0x{n:04X})"),
    }
}

// ── Graceful fallback for unparseable formats ─────────────────────────────────
fn fallback_metadata(
    data: &[u8],
    file_size: u64,
    sha256: String,
    sha1: String,
    md5: String,
    parse_err: &str,
) -> FileMetadata {
    let magic_hex = data
        .get(..4)
        .map(|b| {
            b.iter()
                .map(|x| format!("{x:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|| "??".into());

    let (fmt, _arch_hint) = detect_magic(data);

    let architecture = if fmt == "ELF" {
        elf_arch(data)
    } else {
        fmt.to_string()
    };

    let entropy = shannon_entropy_sampled(&data[..std::cmp::min(data.len(), 1024 * 1024)]);

    FileMetadata {
        file_type: format!("{fmt} [magic: {magic_hex}] — parse error: {parse_err}"),
        architecture,
        entry_point: 0,
        file_size,
        image_base: 0,
        sections: vec![SectionMetadata {
            name: format!("[{fmt}] full file (no section table parsed)"),
            file_offset: 0,
            file_size,
            virtual_address: 0,
            virtual_size: file_size,
            permissions: "---".to_string(),
            entropy,
        }],
        imports_count: 0,
        exports_count: 0,
        symbols_count: 0,
        imports: vec![],
        pe_imports: vec![],
        exports: vec![],
        sha256,
        sha1,
        md5,
    }
}

pub fn inspect_file_metadata(path: String) -> Result<FileMetadata, String> {
    let snapshot = read_inspection_snapshot(&path)?;
    metadata_snapshot(&snapshot)
}

// Keep the legacy multi-format producer unchanged while allowing checked IPC to
// qualify, hash and parse one owned snapshot without reopening the input path.
pub(super) fn metadata_snapshot(data: &[u8]) -> Result<FileMetadata, String> {
    let file_size = data.len() as u64;
    let (sha256, sha1, md5_hash) = compute_hashes(data, file_size)?;
    // Validate PE raw extents and budgets before object parsing, section entropy,
    // symbol enumeration, or any eager import/export metadata allocation.
    let pe_imports = parse_pe_imports(data)?;
    let pe_exports = parse_pe_exports(data)?;
    let pe_section_names = parse_pe_section_names(data)?;
    // Extras are part of the PE inspection contract too. Reject their invalid or
    // over-budget metadata here, even if a UI treats its separate extras fetch as optional.
    parse_pe_extras(data)?;

    // ── 4. Try to parse as a known binary format ───────────────────────────
    let file = match File::parse(data) {
        Ok(f) => f,
        Err(e) => {
            if data.starts_with(b"MZ") {
                return Err(format!("Malformed or unsupported PE input: {e}"));
            }
            return Ok(fallback_metadata(
                data,
                file_size,
                sha256,
                sha1,
                md5_hash,
                &e.to_string(),
            ))
        }
    };

    let file_type = format!("{:?}", file.format());
    let image_base = file.relative_address_base() as u64;
    let entry_point = file.entry();

    let architecture = match file.architecture() {
        Architecture::I386 => "x86".to_string(),
        Architecture::X86_64 => "x64".to_string(),
        Architecture::Arm => "ARM".to_string(),
        Architecture::Aarch64 => "AArch64".to_string(),
        Architecture::PowerPc => "PowerPC".to_string(),
        Architecture::Mips => "MIPS".to_string(),
        other => format!("{other:?}"),
    };

    let is_pe = file.format() == object::BinaryFormat::Pe;
    let mut pe_section_names = pe_section_names.into_iter();
    let sections: Vec<SectionMetadata> = file
        .sections()
        .map(|section| {
            let file_range = section.file_range();
            let sec_offset = file_range.map(|(off, _)| off).unwrap_or(0);
            let sec_size = file_range.map(|(_, sz)| sz).unwrap_or(0);
            let virtual_address = section.address();
            let virtual_size = section.size();
            let perms = format!("{:?}", section.flags());

            let entropy = {
                let range = usize::try_from(sec_offset).ok().and_then(|start| {
                    usize::try_from(sec_size).ok().and_then(|size| start.checked_add(size))
                        .and_then(|end| data.get(start..end))
                });
                range.map(shannon_entropy_sampled).unwrap_or(0.0)
            };

            Ok(SectionMetadata {
                name: if is_pe {
                    pe_section_names.next().ok_or("PE section name count mismatch")?
                } else {
                    section.name().unwrap_or_default().to_string()
                },
                file_offset: sec_offset,
                file_size: sec_size,
                virtual_address,
                virtual_size,
                permissions: perms,
                entropy,
            })
        })
        .collect::<Result<_, String>>()?;
    if is_pe && pe_section_names.next().is_some() {
        return Err("PE section name count mismatch".into());
    }

    let symbols_count = file.symbols().count();

    // PE imports/exports never pass through object's eager unbudgeted vectors.
    // The named-only legacy projection adds at most MAX_PE_TEXT_BYTES of text.
    let imports: Vec<ImportEntry> = if is_pe {
        pe_imports.iter().filter_map(|imp| imp.name.as_ref().map(|name| ImportEntry {
            name: name.clone(), library: imp.dll.clone(),
        })).collect()
    } else {
        file.imports().unwrap_or_default().into_iter().map(|imp| ImportEntry {
            name: String::from_utf8_lossy(imp.name()).into_owned(),
            library: String::from_utf8_lossy(imp.library()).into_owned(),
        }).collect()
    };
    let exports: Vec<ExportEntry> = if is_pe {
        pe_exports.into_iter().map(|exp| ExportEntry {
            name: exp.name, address: exp.address,
        }).collect()
    } else {
        file.exports().unwrap_or_default().into_iter().map(|exp| ExportEntry {
            name: String::from_utf8_lossy(exp.name()).into_owned(), address: exp.address(),
        }).collect()
    };

    Ok(FileMetadata {
        file_type,
        architecture,
        entry_point,
        file_size,
        image_base,
        sections,
        imports_count: imports.len(),
        exports_count: exports.len(),
        symbols_count,
        imports,
        pe_imports,
        exports,
        sha256,
        sha1,
        md5: md5_hash,
    })
}

// ─── PE TLS + Resource Directory ─────────────────────────────────────────────

/// Mach-O load command summary (name only — used to populate the UI).
#[derive(Debug, Clone, Serialize)]
pub struct MachLoadCommand {
    pub cmd: String,
    pub cmdsize: u32,
}

/// Parse bounded, file-backed PE TLS and resources from the same capped snapshot.
/// Non-PE is empty; malformed PE and exhausted budgets are explicit errors.
pub fn inspect_pe_extras(path: String) -> Result<PeExtras, String> {
    let snapshot = read_inspection_snapshot(&path)?;
    parse_pe_extras(&snapshot)
}

/// Returns basic Mach-O load command names for the provided binary.
/// Returns an empty vec for non-Mach-O files.
pub fn inspect_macho_load_commands(path: String) -> Result<Vec<MachLoadCommand>, String> {
    let snapshot = read_inspection_snapshot(&path)?;
    macho_commands_snapshot(&snapshot)
}

pub(super) fn macho_commands_snapshot(data: &[u8]) -> Result<Vec<MachLoadCommand>, String> {

    if data.len() < 4 {
        return Ok(vec![]);
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));

    // Determine Mach-O flavor
    let (is64, swap) = match magic {
        0xFEEDFACF => (true, false),  // MH_MAGIC_64
        0xCFFAEDFE => (true, true),   // MH_CIGAM_64
        0xFEEDFACE => (false, false), // MH_MAGIC
        0xCEFAEDFE => (false, true),  // MH_CIGAM
        _ => return Ok(vec![]),       // Not Mach-O (or fat binary)
    };

    let read32 = |off: usize| -> Option<u32> {
        let raw = u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?);
        Some(if swap { raw.swap_bytes() } else { raw })
    };

    // Mach-O header: magic(4) cpu_type(4) cpu_subtype(4) filetype(4) ncmds(4) sizeofcmds(4) flags(4) [reserved(4) if 64]
    let hdr_size = if is64 { 32usize } else { 28 };
    if data.len() < hdr_size {
        return Ok(vec![]);
    }
    let ncmds = read32(16).unwrap_or(0) as usize;

    let mut offset = hdr_size;
    let mut cmds: Vec<MachLoadCommand> = Vec::with_capacity(ncmds.min(128));

    for _ in 0..ncmds.min(256) {
        let Some(cmd) = read32(offset) else { break };
        let Some(cmdsize) = read32(offset + 4) else {
            break;
        };
        if cmdsize < 8 || offset + cmdsize as usize > data.len() {
            break;
        }

        let cmd_name = match cmd {
            0x01 => "LC_SEGMENT",
            0x02 => "LC_SYMTAB",
            0x04 => "LC_THREAD",
            0x05 => "LC_UNIXTHREAD",
            0x0B => "LC_DYSYMTAB",
            0x0C => "LC_LOAD_DYLIB",
            0x0E => "LC_LOAD_DYLINKER",
            0x11 => "LC_TWOLEVEL_HINTS",
            0x19 => "LC_SEGMENT_64",
            0x1B => "LC_UUID",
            0x1D => "LC_CODE_SIGNATURE",
            0x1E => "LC_SEGMENT_SPLIT_INFO",
            0x20 => "LC_LAZY_LOAD_DYLIB",
            0x21 => "LC_ENCRYPTION_INFO",
            0x22 => "LC_DYLD_INFO",
            0x24 => "LC_VERSION_MIN_MACOSX",
            0x25 => "LC_VERSION_MIN_IPHONEOS",
            0x26 => "LC_FUNCTION_STARTS",
            0x27 => "LC_DYLD_ENVIRONMENT",
            0x28 => "LC_MAIN",
            0x29 => "LC_DATA_IN_CODE",
            0x2A => "LC_SOURCE_VERSION",
            0x2C => "LC_ENCRYPTION_INFO_64",
            0x2D => "LC_LINKER_OPTION",
            0x32 => "LC_BUILD_VERSION",
            _ => "LC_UNKNOWN",
        };

        cmds.push(MachLoadCommand {
            cmd: cmd_name.to_string(),
            cmdsize,
        });
        offset += cmdsize as usize;
    }

    Ok(cmds)
}
