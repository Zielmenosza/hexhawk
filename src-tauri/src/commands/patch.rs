/// QUILL Patch Engine — Milestone 2
///
/// Writes patches to a *copy* of the target binary, never touching the original.
/// Supports: arbitrary byte replacement, NOP sleds, conditional jump inversion (x86/x64).

use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

// ─── Jump inversion tables ────────────────────────────────────────────────────

/// 1-byte conditional jump opcodes and their inverses.
const JUMP_INVERSIONS_1B: &[(u8, u8)] = &[
    (0x70, 0x71), // JO   → JNO
    (0x71, 0x70), // JNO  → JO
    (0x72, 0x73), // JB   → JNB / JAE
    (0x73, 0x72), // JNB  → JB  / JC
    (0x74, 0x75), // JZ   → JNZ / JNE
    (0x75, 0x74), // JNZ  → JZ  / JE
    (0x76, 0x77), // JBE  → JA  / JNBE
    (0x77, 0x76), // JA   → JBE / JNA
    (0x78, 0x79), // JS   → JNS
    (0x79, 0x78), // JNS  → JS
    (0x7A, 0x7B), // JP   → JNP / JPO
    (0x7B, 0x7A), // JNP  → JP  / JPE
    (0x7C, 0x7D), // JL   → JGE / JNL
    (0x7D, 0x7C), // JGE  → JL  / JNGE
    (0x7E, 0x7F), // JLE  → JG  / JNLE
    (0x7F, 0x7E), // JG   → JLE / JNG
];

/// 2-byte (0x0F prefix) conditional jump opcode second bytes and their inverses.
const JUMP_INVERSIONS_2B: &[(u8, u8)] = &[
    (0x80, 0x81), // JO  → JNO
    (0x81, 0x80),
    (0x82, 0x83), // JB  → JNB
    (0x83, 0x82),
    (0x84, 0x85), // JZ  → JNZ
    (0x85, 0x84),
    (0x86, 0x87), // JBE → JA
    (0x87, 0x86),
    (0x88, 0x89), // JS  → JNS
    (0x89, 0x88),
    (0x8A, 0x8B), // JP  → JNP
    (0x8B, 0x8A),
    (0x8C, 0x8D), // JL  → JGE
    (0x8D, 0x8C),
    (0x8E, 0x8F), // JLE → JG
    (0x8F, 0x8E),
];

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct PatchSpec {
    pub offset: u64,
    pub new_bytes: Vec<u8>,
}

#[derive(Debug, serde::Serialize)]
pub struct ExportPatchedResult {
    /// Absolute path to the newly created patched copy.
    pub patched_path: String,
    /// Number of patch specs applied.
    pub patches_applied: usize,
    /// Total bytes modified.
    pub bytes_modified: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct JumpInversionResult {
    /// Whether the bytes at `offset` form an invertible conditional jump.
    pub is_invertible: bool,
    /// Replacement bytes for the opcode (1 or 2 bytes; does not include the rel operand).
    pub inverted_opcode: Vec<u8>,
    /// Human-readable description, e.g. "JZ → JNZ".
    pub description: String,
}

const MAX_PATCH_COUNT: usize = 10_000;
const MAX_SINGLE_PATCH_BYTES: usize = 1024 * 1024; // 1 MB
const MAX_TOTAL_PATCH_BYTES: usize = 16 * 1024 * 1024; // 16 MB

fn validate_source_file(path: &str) -> Result<std::path::PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|e| format!("Invalid source path: {e}"))?;
    let meta = fs::metadata(&canonical)
        .map_err(|e| format!("Failed to stat source path: {e}"))?;
    if !meta.is_file() {
        return Err("Patch source must be a regular file.".to_string());
    }
    Ok(canonical)
}

fn next_patched_dest(src: &Path) -> std::path::PathBuf {
    let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("binary");
    let ext = src.extension().and_then(|s| s.to_str()).unwrap_or("");
    let parent = src.parent().unwrap_or(Path::new("."));

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut counter: u32 = 0;
    loop {
        let new_name = if ext.is_empty() {
            if counter == 0 {
                format!("{}.patched.{}", stem, ts)
            } else {
                format!("{}.patched.{}.{}", stem, ts, counter)
            }
        } else if counter == 0 {
            format!("{}.patched.{}.{}", stem, ts, ext)
        } else {
            format!("{}.patched.{}.{}.{}", stem, ts, counter, ext)
        };
        let candidate = parent.join(new_name);
        if !candidate.exists() {
            return candidate;
        }
        counter = counter.saturating_add(1);
    }
}

// ─── Commands ─────────────────────────────────────────────────────────────────

/// Apply a list of byte patches to a **copy** of `path`.
/// The original is never modified.  Returns the path of the new copy.
#[tauri::command]
pub fn export_patched(path: String, patches: Vec<PatchSpec>) -> Result<ExportPatchedResult, String> {
    if patches.is_empty() {
        return Err("No patches to apply.".into());
    }

    if patches.len() > MAX_PATCH_COUNT {
        return Err(format!("Too many patches ({}), max allowed is {}.", patches.len(), MAX_PATCH_COUNT));
    }

    let src = validate_source_file(&path)?;
    let dest = next_patched_dest(&src);

    let mut data = fs::read(&src).map_err(|e| format!("Failed to read source: {}", e))?;

    let mut bytes_modified = 0usize;
    for patch in &patches {
        if patch.new_bytes.is_empty() {
            return Err(format!("Patch at offset 0x{:X} has empty byte payload.", patch.offset));
        }
        if patch.new_bytes.len() > MAX_SINGLE_PATCH_BYTES {
            return Err(format!(
                "Patch at offset 0x{:X} exceeds max patch size ({} bytes).",
                patch.offset,
                MAX_SINGLE_PATCH_BYTES
            ));
        }
        let start = patch.offset as usize;
        let end = start
            .checked_add(patch.new_bytes.len())
            .ok_or_else(|| format!("Patch at offset 0x{:X} overflows usize bounds", patch.offset))?;
        if end > data.len() {
            return Err(format!(
                "Patch at offset 0x{:X} + {} bytes exceeds file size {}",
                patch.offset,
                patch.new_bytes.len(),
                data.len()
            ));
        }
        data[start..end].copy_from_slice(&patch.new_bytes);
        bytes_modified += patch.new_bytes.len();
        if bytes_modified > MAX_TOTAL_PATCH_BYTES {
            return Err(format!(
                "Total patched bytes exceed max allowed ({} bytes).",
                MAX_TOTAL_PATCH_BYTES
            ));
        }
    }

    let mut out = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&dest)
        .map_err(|e| format!("Failed to create patched file: {}", e))?;
    out.write_all(&data)
        .map_err(|e| format!("Failed to write patched file: {}", e))?;

    Ok(ExportPatchedResult {
        patched_path: dest.to_string_lossy().to_string(),
        patches_applied: patches.len(),
        bytes_modified,
    })
}

/// Reads the bytes at `offset` in `path` and determines whether they form
/// an invertible x86 conditional jump.  Returns the replacement opcode bytes
/// and a human-readable description if so.
#[tauri::command]
pub fn get_jump_inversion(path: String, offset: u64) -> Result<JumpInversionResult, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read: {}", e))?;
    let idx = offset as usize;

    if idx >= data.len() {
        return Ok(JumpInversionResult {
            is_invertible: false,
            inverted_opcode: vec![],
            description: "Offset out of bounds".into(),
        });
    }

    let b0 = data[idx];

    // 1-byte form
    for &(from, to) in JUMP_INVERSIONS_1B {
        if b0 == from {
            let from_name = short_jmp_name(from);
            let to_name   = short_jmp_name(to);
            return Ok(JumpInversionResult {
                is_invertible: true,
                inverted_opcode: vec![to],
                description: format!("{} → {}", from_name, to_name),
            });
        }
    }

    // 2-byte 0F prefix form
    if b0 == 0x0F && idx + 1 < data.len() {
        let b1 = data[idx + 1];
        for &(from, to) in JUMP_INVERSIONS_2B {
            if b1 == from {
                let from_name = long_jmp_name(from);
                let to_name   = long_jmp_name(to);
                return Ok(JumpInversionResult {
                    is_invertible: true,
                    inverted_opcode: vec![0x0F, to],
                    description: format!("{} → {}", from_name, to_name),
                });
            }
        }
    }

    Ok(JumpInversionResult {
        is_invertible: false,
        inverted_opcode: vec![],
        description: format!("Byte 0x{:02X} is not an invertible jump", b0),
    })
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn short_jmp_name(opcode: u8) -> &'static str {
    match opcode {
        0x70 => "JO",  0x71 => "JNO",
        0x72 => "JB",  0x73 => "JNB",
        0x74 => "JZ",  0x75 => "JNZ",
        0x76 => "JBE", 0x77 => "JA",
        0x78 => "JS",  0x79 => "JNS",
        0x7A => "JP",  0x7B => "JNP",
        0x7C => "JL",  0x7D => "JGE",
        0x7E => "JLE", 0x7F => "JG",
        _ => "?",
    }
}

fn long_jmp_name(second_byte: u8) -> &'static str {
    match second_byte {
        0x80 => "JO",  0x81 => "JNO",
        0x82 => "JB",  0x83 => "JNB",
        0x84 => "JZ",  0x85 => "JNZ",
        0x86 => "JBE", 0x87 => "JA",
        0x88 => "JS",  0x89 => "JNS",
        0x8A => "JP",  0x8B => "JNP",
        0x8C => "JL",  0x8D => "JGE",
        0x8E => "JLE", 0x8F => "JG",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn next_patched_dest_has_suffix() {
        let p = Path::new("sample.exe");
        let out = next_patched_dest(p);
        let name = out.file_name().unwrap_or_default().to_string_lossy();
        assert!(name.contains("patched"));
    }

    #[test]
    fn validate_source_file_rejects_missing() {
        let err = validate_source_file("definitely_missing_patch_source.bin").unwrap_err();
        assert!(err.contains("Invalid source path") || err.contains("Failed to stat"));
    }

    #[test]
    fn validate_source_file_rejects_directory() {
        let tmp_dir = std::env::temp_dir().join("hexhawk_patch_test_dir");
        std::fs::create_dir_all(&tmp_dir).expect("create temp dir");
        let err = validate_source_file(tmp_dir.to_string_lossy().as_ref()).unwrap_err();
        assert!(err.contains("regular file"));
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn export_patched_rejects_empty_patch_bytes() {
        let src = std::env::temp_dir().join("hexhawk_patch_src.bin");
        std::fs::write(&src, [0x90, 0x90, 0x90, 0x90]).expect("write source");

        let result = export_patched(
            src.to_string_lossy().to_string(),
            vec![PatchSpec { offset: 0, new_bytes: vec![] }],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty byte payload"));
        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn export_patched_rejects_out_of_bounds_patch() {
        let src = std::env::temp_dir().join("hexhawk_patch_src_oob.bin");
        std::fs::write(&src, [0x90, 0x90, 0x90, 0x90]).expect("write source");

        let result = export_patched(
            src.to_string_lossy().to_string(),
            vec![PatchSpec { offset: 10, new_bytes: vec![0xCC] }],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds file size"));
        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn export_patched_writes_copy_without_modifying_source() {
        let src = std::env::temp_dir().join("hexhawk_patch_src_safe.bin");
        let original = vec![0x90, 0x90, 0x90, 0x90];
        std::fs::write(&src, &original).expect("write source");

        let res = export_patched(
            src.to_string_lossy().to_string(),
            vec![PatchSpec { offset: 1, new_bytes: vec![0xCC] }],
        ).expect("patch export should succeed");

        let src_after = std::fs::read(&src).expect("read source after");
        assert_eq!(src_after, original);

        let patched_path = PathBuf::from(res.patched_path);
        let patched = std::fs::read(&patched_path).expect("read patched file");
        assert_eq!(patched[1], 0xCC);

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&patched_path);
    }
}
