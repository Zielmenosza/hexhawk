use super::pe_imports::{parse_pe_imports, parse_pe_section_names, PeImportEntry};
use capstone::prelude::*;
use memmap2::MmapOptions;
use object::{Architecture, File as ObjectFile, Object, ObjectSection};
use std::fs;

const MAX_DISASSEMBLY_BYTES: usize = 1024 * 1024;
const MAX_DISASSEMBLY_INSTRUCTIONS: usize = 16_384;
const MAX_MAPPED_FILE_BYTES: u64 = 256 * 1024 * 1024;

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
pub(crate) fn capstone_for_arch(
    arch: Architecture,
    data: &[u8],
) -> Result<(Capstone, &'static str, bool), String> {
    let e = |err: capstone::Error| format!("Failed to initialize Capstone: {}", err);
    match arch {
        Architecture::I386 => Ok((
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .build()
                .map_err(e)?,
            "x86",
            false,
        )),
        Architecture::X86_64 => Ok((
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .build()
                .map_err(e)?,
            "x86-64",
            false,
        )),
        Architecture::Arm => {
            // Choose Thumb or ARM mode based on entry point LSB
            if arm_uses_thumb(data) {
                Ok((
                    Capstone::new()
                        .arm()
                        .mode(arch::arm::ArchMode::Thumb)
                        .build()
                        .map_err(e)?,
                    "ARM (Thumb)",
                    false,
                ))
            } else {
                Ok((
                    Capstone::new()
                        .arm()
                        .mode(arch::arm::ArchMode::Arm)
                        .build()
                        .map_err(e)?,
                    "ARM",
                    false,
                ))
            }
        }
        Architecture::Aarch64 => Ok((
            Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .build()
                .map_err(e)?,
            "arm64",
            false,
        )),
        Architecture::Mips => Ok((
            Capstone::new()
                .mips()
                .mode(arch::mips::ArchMode::Mips32)
                .build()
                .map_err(e)?,
            "MIPS",
            false,
        )),
        Architecture::Mips64 => Ok((
            Capstone::new()
                .mips()
                .mode(arch::mips::ArchMode::Mips64)
                .build()
                .map_err(e)?,
            "MIPS64",
            false,
        )),
        Architecture::PowerPc => Ok((
            Capstone::new()
                .ppc()
                .mode(arch::ppc::ArchMode::Mode32)
                .build()
                .map_err(e)?,
            "PowerPC",
            false,
        )),
        Architecture::PowerPc64 => Ok((
            Capstone::new()
                .ppc()
                .mode(arch::ppc::ArchMode::Mode64)
                .build()
                .map_err(e)?,
            "PowerPC64",
            false,
        )),
        // Unsupported: fall back to x86-64, mark as fallback so caller can warn
        _ => Ok((
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .build()
                .map_err(e)?,
            "x86-64 (fallback — architecture not supported)",
            true,
        )),
    }
}

#[derive(Debug, serde::Serialize)]
pub struct DisassemblyResult {
    pub arch: String,
    pub is_fallback: bool,
    pub instructions: Vec<DisassembledInstruction>,
    /// Advisory PE import-table metadata parsed from raw bytes. Empty for non-PE or parse failures.
    pub imports: Vec<PeImportEntry>,
    /// True when more instructions exist beyond the returned chunk.
    pub has_more: bool,
    /// File byte offset to pass as `offset` for the next chunk (0 when `has_more` is false).
    pub next_byte_offset: u64,
    /// Number of bytes that could not be decoded (skipped as data).
    pub bad_bytes: usize,
    /// Advisory limits and architecture-specific caveats.
    pub warnings: Vec<String>,
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
) -> Result<(Vec<DisassembledInstruction>, usize, usize), String> {
    if slice.len() > MAX_DISASSEMBLY_BYTES || limit > MAX_DISASSEMBLY_INSTRUCTIONS {
        return Err("Disassembly decoder budget exceeded".into());
    }
    base_addr
        .checked_add(
            u64::try_from(slice.len())
                .map_err(|_| "Disassembly byte length cannot be represented")?,
        )
        .ok_or("Disassembly address range overflow")?;
    let mut result = Vec::with_capacity(limit.min(slice.len()));
    let mut pos: usize = 0;
    let mut bad_bytes: usize = 0;

    while pos < slice.len() && result.len() < limit {
        let remaining = &slice[pos..];
        let addr = base_addr
            .checked_add(
                u64::try_from(pos)
                    .map_err(|_| "Disassembly byte position cannot be represented")?,
            )
            .ok_or("Disassembly address overflow")?;

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

    Ok((result, bad_bytes, pos))
}

pub(super) fn validate_disassembly_request(
    offset: usize,
    length: usize,
    max_instructions: Option<u64>,
) -> Result<usize, String> {
    offset
        .checked_add(length)
        .ok_or("Disassembly range overflow")?;
    if length > MAX_DISASSEMBLY_BYTES {
        return Err(format!(
            "Disassembly byte budget exceeded (maximum {MAX_DISASSEMBLY_BYTES})"
        ));
    }
    let limit = usize::try_from(max_instructions.unwrap_or(256))
        .map_err(|_| "Disassembly instruction count cannot be represented".to_string())?;
    if limit == 0 || limit > MAX_DISASSEMBLY_INSTRUCTIONS {
        return Err(format!(
            "Disassembly instruction budget must be 1..={MAX_DISASSEMBLY_INSTRUCTIONS}"
        ));
    }
    Ok(limit)
}

// Legacy Rust/CLI entry point. Native IPC uses analysis_bound's checked snapshot.
pub fn disassemble_file_range(
    path: String, offset: usize, length: usize, max_instructions: Option<u64>,
) -> Result<DisassemblyResult, String> {
    validate_disassembly_request(offset, length, max_instructions)?;
    // Bound object/import parsing and the mapping before decoder allocations.
    let file_handle = fs::File::open(&path).map_err(|e| format!("Failed to open file: {e}"))?;
    let file_len = file_handle
        .metadata()
        .map_err(|e| format!("Failed to stat file: {e}"))?
        .len();
    if file_len > MAX_MAPPED_FILE_BYTES {
        return Err(format!(
            "Disassembly file budget exceeded (maximum {MAX_MAPPED_FILE_BYTES} bytes)"
        ));
    }
    let mmap = unsafe {
        MmapOptions::new()
            .len(usize::try_from(file_len).map_err(|_| "File size cannot be represented")?)
            .map(&file_handle)
            .map_err(|e| format!("Failed to mmap file: {e}"))?
    };
    disassemble_snapshot(&mmap, offset, length, max_instructions)
}

pub(super) fn disassemble_snapshot(
    data: &[u8], offset: usize, length: usize, max_instructions: Option<u64>,
) -> Result<DisassemblyResult, String> {
    let limit = validate_disassembly_request(offset, length, max_instructions)?;
    let imports = parse_pe_imports(data)?;
    let pe_section_names = parse_pe_section_names(data)?;

    if offset >= data.len() {
        return Ok(DisassemblyResult {
            arch: "unknown".into(),
            is_fallback: false,
            instructions: vec![],
            imports: vec![],
            has_more: false,
            next_byte_offset: 0,
            bad_bytes: 0,
            warnings: vec![],
        });
    }

    // Auto-detect architecture from file header; fall back to x86-64
    let detected_arch = ObjectFile::parse(data)
        .map(|f| f.architecture())
        .unwrap_or(Architecture::X86_64);

    // If offset == 0 and this is a parsed object, try to snap to the .text section
    // so we skip the PE/ELF header bytes that cause spurious decode failures.
    let (effective_offset, effective_length) = snap_to_text_section(data, offset, length, &pe_section_names)?;

    let end = effective_offset
        .checked_add(effective_length)
        .ok_or("Snapped disassembly range overflow")?
        .min(data.len());
    let slice = &data[effective_offset..end];
    let base_addr =
        u64::try_from(effective_offset).map_err(|_| "Disassembly offset cannot be represented")?;
    let end_file_offset =
        u64::try_from(end).map_err(|_| "Disassembly end cannot be represented")?;

    let (cs, arch_name, is_fallback) = capstone_for_arch(detected_arch, data)?;

    let (instructions, bad_bytes, consumed_bytes) = disasm_robust(&cs, slice, base_addr, limit)?;
    let warnings = architecture_warnings(arch_name);

    let next_byte_offset = if instructions.is_empty() {
        end_file_offset
    } else {
        base_addr
            .checked_add(
                u64::try_from(consumed_bytes)
                    .map_err(|_| "Decoded byte count cannot be represented")?,
            )
            .ok_or("Disassembly next offset overflow")?
    };

    let has_more = next_byte_offset < end_file_offset && instructions.len() == limit;

    Ok(DisassemblyResult {
        arch: arch_name.to_string(),
        is_fallback,
        instructions,
        imports,
        has_more,
        next_byte_offset,
        bad_bytes,
        warnings,
    })
}

/// If the caller starts at offset 0 and the file is a parseable object, advance
/// the offset to the file position of the first executable section (.text / .code)
/// to avoid disassembling the file header.  Returns the original values unchanged
/// if the section cannot be found or the caller chose a non-zero offset.
// Reject malformed raw section extents; never expand the requested byte budget.
fn snap_to_text_section(
    data: &[u8],
    offset: usize,
    length: usize,
    pe_section_names: &[String],
) -> Result<(usize, usize), String> {
    if offset != 0 {
        return Ok((offset, length));
    }
    let Ok(obj) = ObjectFile::parse(data) else {
        return Ok((offset, length));
    };
    let is_pe = obj.format() == object::BinaryFormat::Pe;
    if is_pe && obj.sections().count() != pe_section_names.len() {
        return Err("PE section name count mismatch".into());
    }
    // For PE, never re-enter object's unbounded COFF string-table name scan.
    let sec = obj.sections().enumerate().find(|(index, s)| {
        let name = if is_pe {
            pe_section_names[*index].as_str()
        } else {
            s.name().unwrap_or("")
        };
        name.eq_ignore_ascii_case(".text") || name.eq_ignore_ascii_case(".code") || name.eq_ignore_ascii_case("__text")
    });
    let Some((_, sec)) = sec else {
        return Ok((offset, length));
    };
    // object 0.31 reports min(VirtualSize, SizeOfRawData) for PE. Validate
    // the declared raw extent too, so a small virtual size cannot hide bad bounds.
    let raw_header = if obj.format() == object::BinaryFormat::Pe {
        let sections = if obj.is_64() {
            object::read::pe::PeFile64::parse(data)
                .map_err(|_| "Invalid PE64 header")?
                .section_table()
        } else {
            object::read::pe::PeFile32::parse(data)
                .map_err(|_| "Invalid PE32 header")?
                .section_table()
        };
        Some(
            sections
                .section(sec.index().0)
                .map_err(|_| "Invalid PE text section index")?,
        )
    } else {
        None
    };
    if let Some(header) = raw_header {
        let raw_start = u64::from(header.pointer_to_raw_data.get(object::LittleEndian));
        let raw_size = u64::from(header.size_of_raw_data.get(object::LittleEndian));
        let raw_end = raw_start
            .checked_add(raw_size)
            .ok_or("PE text section range overflow")?;
        if raw_end > u64::try_from(data.len()).map_err(|_| "File size cannot be represented")? {
            return Err("PE text section raw range extends beyond EOF".into());
        }
    }
    let Some((file_offset, file_size)) = sec.file_range() else {
        return Ok((offset, length));
    };
    let start =
        usize::try_from(file_offset).map_err(|_| "Text section offset cannot be represented")?;
    let size = usize::try_from(file_size).map_err(|_| "Text section size cannot be represented")?;
    let section_end = start
        .checked_add(size)
        .ok_or("Text section range overflow")?;
    if section_end > data.len() {
        return Err("Text section range extends beyond EOF".into());
    }
    Ok((start, size.min(length)))
}

fn architecture_warnings(arch_name: &str) -> Vec<String> {
    if arch_name == "arm64" {
        vec!["ARM64 architecture detected. Disassembly available. Import resolution and calling-convention inference are limited for ARM64 in this release.".to_string()]
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn range_fixture(name: &str, data: &[u8]) -> String {
        let path = std::env::var_os("TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("range-disasm-{name}-{}.bin", std::process::id()));
        fs::write(&path, data).expect("write inert fixture");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn range_disasm_rejects_byte_budget_before_decode() {
        let path = range_fixture("bytes", &[0x90]);
        let result = disassemble_file_range(path.clone(), 0, 1024 * 1024 + 1, Some(1));
        let _ = fs::remove_file(path);
        assert!(
            result.is_err(),
            "over-budget requested bytes must fail explicitly"
        );
    }

    #[test]
    fn range_disasm_rejects_instruction_budget_before_allocation() {
        let path = range_fixture("instructions", &[0x90]);
        let result = disassemble_file_range(path.clone(), 0, 1, Some(16_385));
        let _ = fs::remove_file(path);
        assert!(
            result.is_err(),
            "over-budget instruction count must be rejected"
        );
    }

    #[test]
    fn range_disasm_rejects_unrepresentable_budget_even_at_eof() {
        let path = range_fixture("conversion", &[0x90]);
        let result = disassemble_file_range(path.clone(), 1, 1, Some(u64::MAX));
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn range_disasm_rejects_offset_overflow() {
        let path = range_fixture("overflow", &[0x90, 0x90]);
        let result = disassemble_file_range(path.clone(), 1, usize::MAX, Some(1));
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn range_disasm_snap_respects_requested_length() {
        let path = range_fixture("snap-length", &minimal_elf64_aarch64_text());
        let result = disassemble_file_range(path.clone(), 0, 4, Some(8));
        let _ = fs::remove_file(path);
        let result = result.expect("bounded snapped decode");
        assert_eq!(result.instructions.len(), 1);
        assert_eq!(result.next_byte_offset, 0x104);
    }

    #[test]
    fn range_disasm_rejects_snapped_section_beyond_eof() {
        let mut data = minimal_elf64_aarch64_text();
        put_u64(&mut data, 0x128 + 64 + 0x18, 0x1000);
        let path = range_fixture("snap-eof", &data);
        let result = disassemble_file_range(path.clone(), 0, 4, Some(8));
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn range_disasm_rejects_snapped_section_size_overflow() {
        let mut data = minimal_elf64_aarch64_text();
        put_u64(&mut data, 0x128 + 64 + 0x20, u64::MAX);
        let path = range_fixture("snap-overflow", &data);
        let result = disassemble_file_range(path.clone(), 0, 4, Some(8));
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn range_disasm_pe64_snap_is_bounded_and_zero_length_is_empty() {
        let path = range_fixture("pe64", &range_pe64_text());
        let result = disassemble_file_range(path.clone(), 0, 1, Some(8)).unwrap();
        assert_eq!(result.arch, "x86-64");
        assert_eq!(result.instructions.len(), 1);
        assert_eq!(result.instructions[0].address, 0x200);
        assert_eq!(result.next_byte_offset, 0x201);
        assert!(!result.has_more);
        let empty = disassemble_file_range(path.clone(), 0, 0, Some(8)).unwrap();
        let _ = fs::remove_file(path);
        assert!(empty.instructions.is_empty());
        assert!(!empty.has_more);
    }

    #[test]
    fn range_disasm_pe64_rejects_raw_section_extent_beyond_eof() {
        let mut data = range_pe64_text();
        put_u32(&mut data, 0x198, u32::MAX);
        let path = range_fixture("pe64-eof", &data);
        let result = disassemble_file_range(path.clone(), 0, 1, Some(8));
        let _ = fs::remove_file(path);
        assert!(result.unwrap_err().contains("beyond EOF"));
    }

    #[test]
    fn range_disasm_accepts_exact_instruction_budget_and_rejects_zero() {
        let path = range_fixture("exact-instructions", &vec![0x90; 16_385]);
        let result = disassemble_file_range(path.clone(), 0, 16_385, Some(16_384)).unwrap();
        assert_eq!(result.instructions.len(), 16_384);
        assert!(result.has_more);
        assert_eq!(result.next_byte_offset, 16_384);
        assert!(disassemble_file_range(path.clone(), 0, 1, Some(0)).is_err());
        let _ = fs::remove_file(path);
    }

    fn range_pe64_text() -> Vec<u8> {
        let mut data = vec![0u8; 0x220];
        data[0..2].copy_from_slice(b"MZ");
        put_u32(&mut data, 0x3C, 0x80);
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        put_u16(&mut data, 0x84, 0x8664);
        put_u16(&mut data, 0x86, 1);
        put_u16(&mut data, 0x94, 0xF0);
        put_u16(&mut data, 0x96, 0x22);
        put_u16(&mut data, 0x98, 0x20B);
        put_u32(&mut data, 0xA8, 0x1000);
        put_u64(&mut data, 0xB0, 0x140000000);
        put_u32(&mut data, 0xB8, 0x1000);
        put_u32(&mut data, 0xBC, 0x200);
        put_u32(&mut data, 0xD0, 0x2000);
        put_u32(&mut data, 0xD4, 0x200);
        put_u32(&mut data, 0x104, 16);
        data[0x188..0x190].copy_from_slice(b".text\0\0\0");
        put_u32(&mut data, 0x190, 7);
        put_u32(&mut data, 0x194, 0x1000);
        put_u32(&mut data, 0x198, 7);
        put_u32(&mut data, 0x19C, 0x200);
        put_u32(&mut data, 0x1AC, 0x60000020);
        data[0x200..0x207].copy_from_slice(&[0x90, 0xB8, 1, 0, 0, 0, 0xC3]);
        assert_eq!(
            ObjectFile::parse(data.as_slice())
                .expect("valid PE64")
                .architecture(),
            Architecture::X86_64
        );
        data
    }

    fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn minimal_elf64_aarch64_text() -> Vec<u8> {
        let mut data = vec![0u8; 0x248];
        data[0..4].copy_from_slice(b"\x7FELF");
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // little endian
        data[6] = 1; // version
        put_u16(&mut data, 0x10, 2); // ET_EXEC
        put_u16(&mut data, 0x12, 183); // EM_AARCH64
        put_u32(&mut data, 0x14, 1);
        put_u64(&mut data, 0x18, 0x400000);
        put_u64(&mut data, 0x28, 0x128); // section header offset
        put_u16(&mut data, 0x34, 64);
        put_u16(&mut data, 0x3A, 64);
        put_u16(&mut data, 0x3C, 3);
        put_u16(&mut data, 0x3E, 2);

        data[0x100..0x104].copy_from_slice(&[0xC0, 0x03, 0x5F, 0xD6]); // ret
        data[0x104..0x108].copy_from_slice(&[0x1F, 0x20, 0x03, 0xD5]); // nop
        data[0x108..0x119].copy_from_slice(b"\0.text\0.shstrtab\0");

        let sh_text = 0x128 + 64;
        put_u32(&mut data, sh_text, 1); // name .text
        put_u32(&mut data, sh_text + 4, 1); // SHT_PROGBITS
        put_u64(&mut data, sh_text + 8, 0x6); // alloc + exec
        put_u64(&mut data, sh_text + 0x10, 0x400000);
        put_u64(&mut data, sh_text + 0x18, 0x100);
        put_u64(&mut data, sh_text + 0x20, 8);
        put_u64(&mut data, sh_text + 0x30, 4);

        let sh_names = 0x128 + 128;
        put_u32(&mut data, sh_names, 7); // name .shstrtab
        put_u32(&mut data, sh_names + 4, 3); // SHT_STRTAB
        put_u64(&mut data, sh_names + 0x18, 0x108);
        put_u64(&mut data, sh_names + 0x20, 0x11);
        data
    }

    #[test]
    fn valid_arm64_elf_disassembles_with_honest_warning() {
        let path = std::env::temp_dir().join("hexhawk-arm64-test.elf");
        fs::write(&path, minimal_elf64_aarch64_text()).expect("write elf");
        let result = disassemble_file_range(path.to_string_lossy().to_string(), 0, 0x200, Some(8))
            .expect("disassemble");
        let _ = fs::remove_file(path);

        assert_eq!(result.arch, "arm64");
        assert!(!result.is_fallback);
        assert!(result.instructions.iter().any(|ins| ins.mnemonic == "ret"));
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("ARM64 architecture detected")));
    }

    #[test]
    fn x86_64_capstone_arch_is_unchanged_and_has_no_arm64_warning() {
        let (_cs, arch, fallback) = capstone_for_arch(Architecture::X86_64, &[]).expect("capstone");
        assert_eq!(arch, "x86-64");
        assert!(!fallback);
        assert!(architecture_warnings(arch).is_empty());
    }

    #[test]
    fn x86_pagination_advances_by_decoded_instruction_length() {
        let path = std::env::temp_dir().join("hexhawk-x86-pagination.bin");
        // NOP; MOV EAX,1 (5 bytes); RET. The second page must resume at offset 6,
        // not offset 2, otherwise it starts in the middle of the MOV immediate.
        fs::write(&path, [0x90, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]).expect("write fixture");
        let result = disassemble_file_range(path.to_string_lossy().to_string(), 0, 7, Some(2))
            .expect("disassemble");
        let _ = fs::remove_file(path);

        assert_eq!(result.instructions.len(), 2);
        assert_eq!(result.instructions[0].address, 0);
        assert_eq!(result.instructions[0].mnemonic, "nop");
        assert_eq!(result.instructions[1].address, 1);
        assert_eq!(result.instructions[1].mnemonic, "mov");
        assert_eq!(result.next_byte_offset, 6);
        assert!(result.has_more);
    }
}
