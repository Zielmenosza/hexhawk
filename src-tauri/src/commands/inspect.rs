use object::{Architecture, File, Object, ObjectSection};
use serde::Serialize;
use std::fs;
use sha2::{Sha256, Digest};
use md5::Md5;

fn shannon_entropy(bytes: &[u8]) -> f64 {
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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::shannon_entropy;

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
    pub exports: Vec<ExportEntry>,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

#[tauri::command]
pub fn inspect_file_metadata(path: String) -> Result<FileMetadata, String> {
    let data = fs::read(&path).map_err(|err| format!("Failed to read file: {}", err))?;

    const MAX_FILE_SIZE_BYTES: usize = 512 * 1024 * 1024; // 512 MB
    if data.len() > MAX_FILE_SIZE_BYTES {
        return Err(format!(
            "File exceeds maximum size limit of {} MB for metadata inspection.",
            MAX_FILE_SIZE_BYTES / (1024 * 1024)
        ));
    }

    // Calculate hashes
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        format!("{:x}", hasher.finalize())
    };
    
    let sha1 = {
        let mut hasher = sha1::Sha1::new();
        hasher.update(&data);
        format!("{:x}", hasher.finalize())
    };
    
    let md5_hash = {
        let mut hasher = Md5::new();
        hasher.update(&data);
        format!("{:x}", hasher.finalize())
    };
    
    let file_size = data.len() as u64;
    
    let file = File::parse(&*data).map_err(|err| format!("Failed to parse object file: {}", err))?;

    let file_type = format!("{:?}", file.format());
    let image_base = file.relative_address_base() as u64;

    let architecture = match file.architecture() {
        Architecture::I386 => "x86".to_string(),
        Architecture::X86_64 => "x64".to_string(),
        Architecture::Arm => "ARM".to_string(),
        Architecture::Aarch64 => "AArch64".to_string(),
        Architecture::PowerPc => "PowerPC".to_string(),
        Architecture::Mips => "MIPS".to_string(),
        other => format!("{:?}", other),
    };

    let entry_point = file.entry();

    let sections: Vec<SectionMetadata> = file
        .sections()
        .map(|section| {
            let file_range = section.file_range();
            let file_offset = file_range.map(|(off, _)| off).unwrap_or(0);
            let file_size = file_range.map(|(_, sz)| sz).unwrap_or(0);
            let virtual_address = section.address();
            let virtual_size = section.size();
            
            // Try to determine permissions
            let perms = {
                let flags = section.flags();
                format!("{:?}", flags)
            };

            let entropy = {
                let start = file_offset as usize;
                let end = std::cmp::min(start + file_size as usize, data.len());
                if start < end { shannon_entropy(&data[start..end]) } else { 0.0 }
            };
            
            SectionMetadata {
                name: section.name().unwrap_or_default().to_string(),
                file_offset,
                file_size,
                virtual_address,
                virtual_size,
                permissions: perms,
                entropy,
            }
        })
        .collect();

    // Count symbols (basic approximation)
    let symbols_count = file.symbols().count();

    let imports: Vec<ImportEntry> = file.imports()
        .unwrap_or_default()
        .into_iter()
        .map(|imp| ImportEntry {
            name: String::from_utf8_lossy(imp.name()).into_owned(),
            library: String::from_utf8_lossy(imp.library()).into_owned(),
        })
        .collect();

    let exports: Vec<ExportEntry> = file.exports()
        .unwrap_or_default()
        .into_iter()
        .map(|exp| ExportEntry {
            name: String::from_utf8_lossy(exp.name()).into_owned(),
            address: exp.address(),
        })
        .collect();

    let imports_count = imports.len();
    let exports_count = exports.len();

    Ok(FileMetadata {
        file_type,
        architecture,
        entry_point,
        file_size,
        image_base,
        sections,
        imports_count,
        exports_count,
        symbols_count,
        imports,
        exports,
        sha256,
        sha1,
        md5: md5_hash,
    })
}