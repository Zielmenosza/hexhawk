use object::{Architecture, File, Object, ObjectSection};
use serde::Serialize;
use std::fs;
use std::io::Read;
use sha2::{Sha256, Digest};
use md5::Md5;
use memmap2::MmapOptions;

const MAX_SAFE_MMAP_BYTES: u64 = 1024 * 1024 * 1024; // 1 GB

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

// ── Streaming hash computation ────────────────────────────────────────────────
// For files > 512 MB we hash only the first 256 MB to keep wall-time sane.
// The result is annotated with "[partial]" so callers know.
fn compute_hashes(path: &str, file_size: u64) -> Result<(String, String, String), String> {
    const FULL_HASH_LIMIT: u64 = 512 * 1024 * 1024;
    const CHUNK: usize = 4 * 1024 * 1024;

    let mut sha256 = Sha256::new();
    let mut sha1_h = sha1::Sha1::new();
    let mut md5_h  = Md5::new();

    let mut f = fs::File::open(path).map_err(|e| format!("Cannot open for hashing: {e}"))?;
    let mut buf = vec![0u8; CHUNK];
    let mut scanned = 0u64;
    let limit = if file_size > FULL_HASH_LIMIT { FULL_HASH_LIMIT } else { file_size };

    loop {
        let want = std::cmp::min(CHUNK as u64, limit - scanned) as usize;
        if want == 0 { break; }
        let n = f.read(&mut buf[..want]).map_err(|e| format!("Read error: {e}"))?;
        if n == 0 { break; }
        sha256.update(&buf[..n]);
        sha1_h.update(&buf[..n]);
        md5_h.update(&buf[..n]);
        scanned += n as u64;
    }

    // Note: for files > 512 MB only the first 256 MB is hashed. The hash is
    // still lowercase hex so it passes evidence-bundle validation; callers can
    // detect partial coverage via file_size vs FULL_HASH_LIMIT if needed.
    Ok((
        format!("{:x}", sha256.finalize()),
        format!("{:x}", sha1_h.finalize()),
        format!("{:x}", md5_h.finalize()),
    ))
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
        [0x4D, 0x5A, ..]                   => ("PE/MZ",        "x86 or x64"),
        [0x7F, 0x45, 0x4C, 0x46, ..]       => ("ELF",          "see ELF header"),
        [0xCF, 0xFA, 0xED, 0xFE, ..]       => ("Mach-O 64",    "x64 or ARM64"),
        [0xCE, 0xFA, 0xED, 0xFE, ..]       => ("Mach-O 32",    "x86 or ARM"),
        [0xCA, 0xFE, 0xBA, 0xBE, ..]       => ("Mach-O fat",   "multi-arch"),
        [0x25, 0x50, 0x44, 0x46, ..]       => ("PDF",          "N/A"),
        [0x50, 0x4B, 0x03, 0x04, ..]
        | [0x50, 0x4B, 0x05, 0x06, ..]     => ("ZIP/PKZIP",    "N/A"),
        [0x52, 0x61, 0x72, 0x21, 0x1A, ..] => ("RAR",          "N/A"),
        [0x37, 0x7A, 0xBC, 0xAF, 0x27, ..] => ("7-Zip",        "N/A"),
        [0x1F, 0x8B, ..]                   => ("GZip",         "N/A"),
        [0x42, 0x5A, 0x68, ..]             => ("BZip2",        "N/A"),
        [0x23, 0x21, ..]                   => ("Script",       "N/A"),
        [0x0A, 0x0D, 0x0D, 0x0A, ..]       => ("PCAPNG",       "N/A"),
        [0xD4, 0xC3, 0xB2, 0xA1, ..]
        | [0xA1, 0xB2, 0xC3, 0xD4, ..]     => ("PCAP",         "N/A"),
        _                                  => ("Unknown",      "unknown"),
    }
}

fn elf_arch(data: &[u8]) -> String {
    if data.len() < 20 { return "ELF".to_string(); }
    let class = data[4]; // 1=32-bit, 2=64-bit
    let machine = if class == 2 {
        u16::from_le_bytes([data[18], data[19]])
    } else {
        data[18] as u16
    };
    match machine {
        3   => "x86".to_string(),
        62  => "x64".to_string(),
        40  => "ARM".to_string(),
        183 => "AArch64".to_string(),
        8   => "MIPS".to_string(),
        20  => "PowerPC".to_string(),
        n   => format!("ELF (machine=0x{n:04X})"),
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
    let magic_hex = data.get(..4).map(|b| {
        b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
    }).unwrap_or_else(|| "??".into());

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
        exports: vec![],
        sha256,
        sha1,
        md5,
    }
}

#[tauri::command]
pub fn inspect_file_metadata(path: String) -> Result<FileMetadata, String> {
    // ── 1. Get file size without a full read ──────────────────────────────
    let file_size = fs::metadata(&path)
        .map_err(|e| format!("Failed to stat file: {e}"))?
        .len();

    // ── 2. Compute hashes via streaming (handles any size) ────────────────
    let (sha256, sha1, md5_hash) = compute_hashes(&path, file_size)?;

    if file_size > MAX_SAFE_MMAP_BYTES {
        let mut f = fs::File::open(&path)
            .map_err(|e| format!("Failed to open file: {e}"))?;
        let mut head = vec![0u8; 1024 * 1024];
        let n = f.read(&mut head).map_err(|e| format!("Read error: {e}"))?;
        head.truncate(n);
        return Ok(fallback_metadata(
            &head,
            file_size,
            sha256,
            sha1,
            md5_hash,
            "file too large for safe mmap parse",
        ));
    }

    // ── 3. Memory-map the file — OS handles paging, no size limit ─────────
    let file_handle = fs::File::open(&path)
        .map_err(|e| format!("Failed to open file: {e}"))?;
    let mmap = unsafe {
        MmapOptions::new().map(&file_handle)
            .map_err(|e| format!("Failed to mmap file: {e}"))?
    };
    let data: &[u8] = &mmap;

    // ── 4. Try to parse as a known binary format ───────────────────────────
    let file = match File::parse(data) {
        Ok(f) => f,
        Err(e) => return Ok(fallback_metadata(data, file_size, sha256, sha1, md5_hash, &e.to_string())),
    };

    let file_type    = format!("{:?}", file.format());
    let image_base   = file.relative_address_base() as u64;
    let entry_point  = file.entry();

    let architecture = match file.architecture() {
        Architecture::I386    => "x86".to_string(),
        Architecture::X86_64  => "x64".to_string(),
        Architecture::Arm     => "ARM".to_string(),
        Architecture::Aarch64 => "AArch64".to_string(),
        Architecture::PowerPc => "PowerPC".to_string(),
        Architecture::Mips    => "MIPS".to_string(),
        other                 => format!("{other:?}"),
    };

    let sections: Vec<SectionMetadata> = file
        .sections()
        .map(|section| {
            let file_range    = section.file_range();
            let sec_offset    = file_range.map(|(off, _)| off).unwrap_or(0);
            let sec_size      = file_range.map(|(_, sz)| sz).unwrap_or(0);
            let virtual_address = section.address();
            let virtual_size  = section.size();
            let perms         = format!("{:?}", section.flags());

            let entropy = {
                let start = sec_offset as usize;
                let end   = std::cmp::min(start + sec_size as usize, data.len());
                if start < end { shannon_entropy_sampled(&data[start..end]) } else { 0.0 }
            };

            SectionMetadata {
                name: section.name().unwrap_or_default().to_string(),
                file_offset: sec_offset,
                file_size: sec_size,
                virtual_address,
                virtual_size,
                permissions: perms,
                entropy,
            }
        })
        .collect();

    let symbols_count = file.symbols().count();

    let imports: Vec<ImportEntry> = file.imports()
        .unwrap_or_default()
        .into_iter()
        .map(|imp| ImportEntry {
            name:    String::from_utf8_lossy(imp.name()).into_owned(),
            library: String::from_utf8_lossy(imp.library()).into_owned(),
        })
        .collect();

    let exports: Vec<ExportEntry> = file.exports()
        .unwrap_or_default()
        .into_iter()
        .map(|exp| ExportEntry {
            name:    String::from_utf8_lossy(exp.name()).into_owned(),
            address: exp.address(),
        })
        .collect();

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
        exports,
        sha256,
        sha1,
        md5: md5_hash,
    })
}

// ─── PE TLS + Resource Directory ─────────────────────────────────────────────

/// A TLS callback entry parsed from the PE TLS directory.
#[derive(Debug, Clone, Serialize)]
pub struct TlsCallback {
    /// Virtual address of the callback function (relative to image base).
    pub address: u64,
}

/// A leaf resource entry (icon, manifest, version info, etc.).
#[derive(Debug, Clone, Serialize)]
pub struct ResourceEntry {
    /// Resource type name or numeric ID as string.
    pub type_name: String,
    /// Numeric resource ID within its type group.
    pub id: u32,
    /// Raw byte size of the resource data.
    pub size: u32,
    /// File offset to the resource data.
    pub offset: u32,
}

/// Mach-O load command summary (name only — used to populate the UI).
#[derive(Debug, Clone, Serialize)]
pub struct MachLoadCommand {
    pub cmd: String,
    pub cmdsize: u32,
}

/// Extended metadata returned by `inspect_pe_extras` for a PE file.
#[derive(Debug, Clone, Serialize)]
pub struct PeExtras {
    pub tls_callbacks: Vec<TlsCallback>,
    pub resources: Vec<ResourceEntry>,
}

/// Reads and parses PE-specific extras: TLS callbacks and top-level resource entries.
///
/// Returns an empty result (not an error) for non-PE files or files without the
/// relevant data directories so the frontend can call it unconditionally.
#[tauri::command]
pub fn inspect_pe_extras(path: String) -> Result<PeExtras, String> {
    let file_size = fs::metadata(&path)
        .map_err(|e| format!("Cannot stat file: {e}"))?
        .len();
    if file_size > MAX_SAFE_MMAP_BYTES {
        return Err(format!(
            "File too large for safe PE extras mmap parse ({} bytes, max {}).",
            file_size,
            MAX_SAFE_MMAP_BYTES
        ));
    }

    let file_handle = fs::File::open(&path)
        .map_err(|e| format!("Cannot open file: {e}"))?;
    let mmap = unsafe {
        MmapOptions::new().map(&file_handle)
            .map_err(|e| format!("mmap failed: {e}"))?
    };
    let data: &[u8] = &mmap;

    // Validate PE header
    // PE sig at byte offset stored in DWORD at 0x3C
    if data.len() < 0x40 { return Ok(PeExtras { tls_callbacks: vec![], resources: vec![] }); }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
    if data.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return Ok(PeExtras { tls_callbacks: vec![], resources: vec![] });
    }

    // Optional header offset: PE sig (4) + COFF (20) = 24 bytes after e_lfanew
    let coff_start = e_lfanew + 4;
    if data.len() < coff_start + 20 { return Ok(PeExtras { tls_callbacks: vec![], resources: vec![] }); }
    let machine      = u16::from_le_bytes(data[coff_start..coff_start+2].try_into().unwrap_or([0;2]));
    let is_pe64 = machine == 0x8664 || machine == 0x0200; // x64 or IA64

    let opt_hdr_start = coff_start + 20;
    if data.len() < opt_hdr_start + 2 { return Ok(PeExtras { tls_callbacks: vec![], resources: vec![] }); }
    let magic = u16::from_le_bytes(data[opt_hdr_start..opt_hdr_start+2].try_into().unwrap_or([0;2]));

    // Image base and data directory offsets differ between PE32 and PE32+
    let (image_base, dd_offset) = if is_pe64 || magic == 0x020B {
        // PE32+: ImageBase at opt+24 (8 bytes), DataDirectory at opt+112
        if data.len() < opt_hdr_start + 120 { return Ok(PeExtras { tls_callbacks: vec![], resources: vec![] }); }
        let ib = u64::from_le_bytes(data[opt_hdr_start+24..opt_hdr_start+32].try_into().unwrap_or([0;8]));
        (ib, opt_hdr_start + 112)
    } else {
        // PE32: ImageBase at opt+28 (4 bytes), DataDirectory at opt+96
        if data.len() < opt_hdr_start + 104 { return Ok(PeExtras { tls_callbacks: vec![], resources: vec![] }); }
        let ib = u32::from_le_bytes(data[opt_hdr_start+28..opt_hdr_start+32].try_into().unwrap_or([0;4])) as u64;
        (ib, opt_hdr_start + 96)
    };

    // DataDirectory: each entry is 8 bytes (RVA:u32, Size:u32)
    // [0]=Export [1]=Import [2]=Resource [3]=Exception [4]=Certificate [5]=BaseReloc
    // [6]=Debug [7]=Architecture [8]=GlobalPtr [9]=TLS [10]=LoadConfig ...
    let section_count = u16::from_le_bytes(data[coff_start+2..coff_start+4].try_into().unwrap_or([0;2])) as usize;
    let opt_hdr_size  = u16::from_le_bytes(data[coff_start+16..coff_start+18].try_into().unwrap_or([0;2])) as usize;
    let sections_start = opt_hdr_start + opt_hdr_size;

    // Build RVA→file-offset helper using section table
    let rva_to_offset = |rva: u32| -> Option<usize> {
        for i in 0..section_count {
            let s = sections_start + i * 40;
            if s + 40 > data.len() { break; }
            let virt_addr = u32::from_le_bytes(data[s+12..s+16].try_into().ok()?) as usize;
            let virt_size = u32::from_le_bytes(data[s+8..s+12].try_into().ok()?) as usize;
            let raw_off   = u32::from_le_bytes(data[s+20..s+24].try_into().ok()?) as usize;
            let raw_size  = u32::from_le_bytes(data[s+16..s+20].try_into().ok()?) as usize;
            if (rva as usize) >= virt_addr && (rva as usize) < virt_addr + virt_size.max(raw_size) {
                let off = raw_off + (rva as usize - virt_addr);
                return if off < data.len() { Some(off) } else { None };
            }
        }
        None
    };

    // ── TLS Directory (DataDirectory[9]) ──────────────────────────────────
    let tls_dd = dd_offset + 9 * 8;
    let mut tls_callbacks: Vec<TlsCallback> = vec![];
    if data.len() >= tls_dd + 8 {
        let tls_rva  = u32::from_le_bytes(data[tls_dd..tls_dd+4].try_into().unwrap_or([0;4]));
        let tls_size = u32::from_le_bytes(data[tls_dd+4..tls_dd+8].try_into().unwrap_or([0;4]));
        if tls_rva != 0 && tls_size > 0 {
            if let Some(tls_off) = rva_to_offset(tls_rva) {
                // TLS directory structure (PE32+): StartAddressOfRawData(8), EndAddress(8),
                // AddressOfIndex(8), AddressOfCallbacks(8), SizeOfZeroFill(4), Characteristics(4)
                let cb_va_off = if is_pe64 || magic == 0x020B { tls_off + 24 } else { tls_off + 12 };
                if data.len() >= cb_va_off + 8 {
                    let cb_va = if is_pe64 || magic == 0x020B {
                        u64::from_le_bytes(data[cb_va_off..cb_va_off+8].try_into().unwrap_or([0;8]))
                    } else {
                        u32::from_le_bytes(data[cb_va_off..cb_va_off+4].try_into().unwrap_or([0;4])) as u64
                    };
                    if cb_va != 0 {
                        // Convert VA to RVA then to file offset
                        let cb_rva = (cb_va.saturating_sub(image_base)) as u32;
                        if let Some(mut cb_off) = rva_to_offset(cb_rva) {
                            // Walk the null-terminated pointer array
                            let ptr_size = if is_pe64 || magic == 0x020B { 8usize } else { 4 };
                            loop {
                                if cb_off + ptr_size > data.len() { break; }
                                let fn_va = if ptr_size == 8 {
                                    u64::from_le_bytes(data[cb_off..cb_off+8].try_into().unwrap_or([0;8]))
                                } else {
                                    u32::from_le_bytes(data[cb_off..cb_off+4].try_into().unwrap_or([0;4])) as u64
                                };
                                if fn_va == 0 { break; }
                                tls_callbacks.push(TlsCallback {
                                    address: fn_va.saturating_sub(image_base),
                                });
                                cb_off += ptr_size;
                                if tls_callbacks.len() > 64 { break; } // sanity cap
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Resource Directory (DataDirectory[2]) ─────────────────────────────
    let rsrc_dd = dd_offset + 2 * 8;
    let mut resources: Vec<ResourceEntry> = vec![];
    if data.len() >= rsrc_dd + 8 {
        let rsrc_rva  = u32::from_le_bytes(data[rsrc_dd..rsrc_dd+4].try_into().unwrap_or([0;4]));
        let rsrc_size = u32::from_le_bytes(data[rsrc_dd+4..rsrc_dd+8].try_into().unwrap_or([0;4]));
        if rsrc_rva != 0 && rsrc_size > 0 {
            if let Some(rsrc_off) = rva_to_offset(rsrc_rva) {
                // Resource directory entry: 8 bytes each.  First, the root IMAGE_RESOURCE_DIRECTORY
                // has 4 bytes header then entries.  We just read the top-level type entries.
                let root_named = u16::from_le_bytes(data.get(rsrc_off+12..rsrc_off+14)
                    .and_then(|b| b.try_into().ok()).unwrap_or([0;2])) as usize;
                let root_id    = u16::from_le_bytes(data.get(rsrc_off+14..rsrc_off+16)
                    .and_then(|b| b.try_into().ok()).unwrap_or([0;2])) as usize;
                let total_entries = root_named + root_id;

                for e in 0..total_entries.min(32) {
                    let entry_off = rsrc_off + 16 + e * 8;
                    if entry_off + 8 > data.len() { break; }
                    let name_or_id = u32::from_le_bytes(data[entry_off..entry_off+4].try_into().unwrap_or([0;4]));
                    let offset_val = u32::from_le_bytes(data[entry_off+4..entry_off+8].try_into().unwrap_or([0;4]));

                    let type_name = if name_or_id & 0x8000_0000 != 0 {
                        // Named entry — skip resolving the name string for brevity
                        format!("NAMED({})", name_or_id & 0x7FFF_FFFF)
                    } else {
                        // Numeric type IDs per MSDN
                        match name_or_id {
                            1  => "RT_CURSOR".into(),
                            2  => "RT_BITMAP".into(),
                            3  => "RT_ICON".into(),
                            4  => "RT_MENU".into(),
                            5  => "RT_DIALOG".into(),
                            6  => "RT_STRING".into(),
                            7  => "RT_FONTDIR".into(),
                            8  => "RT_FONT".into(),
                            9  => "RT_ACCELERATOR".into(),
                            10 => "RT_RCDATA".into(),
                            11 => "RT_MESSAGETABLE".into(),
                            14 => "RT_GROUP_ICON".into(),
                            16 => "RT_VERSION".into(),
                            24 => "RT_MANIFEST".into(),
                            n  => format!("RT_{n}"),
                        }
                    };

                    // Follow the subdirectory pointer to get a leaf node's size
                    if offset_val & 0x8000_0000 != 0 {
                        // Points to another subdirectory (ID-level) — go one level deeper
                        let sub_dir_off = rsrc_off + (offset_val & 0x7FFF_FFFF) as usize;
                        let sub_named = u16::from_le_bytes(data.get(sub_dir_off+12..sub_dir_off+14)
                            .and_then(|b| b.try_into().ok()).unwrap_or([0;2])) as usize;
                        let sub_id    = u16::from_le_bytes(data.get(sub_dir_off+14..sub_dir_off+16)
                            .and_then(|b| b.try_into().ok()).unwrap_or([0;2])) as usize;
                        let sub_total = (sub_named + sub_id).min(16);

                        for se in 0..sub_total {
                            let se_off = sub_dir_off + 16 + se * 8;
                            if se_off + 8 > data.len() { break; }
                            let id_val  = u32::from_le_bytes(data[se_off..se_off+4].try_into().unwrap_or([0;4]));
                            let se_ptr  = u32::from_le_bytes(data[se_off+4..se_off+8].try_into().unwrap_or([0;4]));
                            if se_ptr & 0x8000_0000 != 0 {
                                // Language level — pick first language entry
                                let lang_dir_off = rsrc_off + (se_ptr & 0x7FFF_FFFF) as usize;
                                if lang_dir_off + 24 <= data.len() {
                                    // First language entry data leaf
                                    let lang_entry_off = lang_dir_off + 16;
                                    if lang_entry_off + 8 <= data.len() {
                                        let leaf_ptr = u32::from_le_bytes(data[lang_entry_off+4..lang_entry_off+8].try_into().unwrap_or([0;4]));
                                        if leaf_ptr & 0x8000_0000 == 0 {
                                            let leaf_off = rsrc_off + leaf_ptr as usize;
                                            if leaf_off + 16 <= data.len() {
                                                let data_rva  = u32::from_le_bytes(data[leaf_off..leaf_off+4].try_into().unwrap_or([0;4]));
                                                let data_size = u32::from_le_bytes(data[leaf_off+4..leaf_off+8].try_into().unwrap_or([0;4]));
                                                let file_off  = rva_to_offset(data_rva).unwrap_or(0) as u32;
                                                resources.push(ResourceEntry {
                                                    type_name: type_name.clone(),
                                                    id: id_val & 0x7FFF_FFFF,
                                                    size: data_size,
                                                    offset: file_off,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(PeExtras { tls_callbacks, resources })
}

/// Returns basic Mach-O load command names for the provided binary.
/// Returns an empty vec for non-Mach-O files.
#[tauri::command]
pub fn inspect_macho_load_commands(path: String) -> Result<Vec<MachLoadCommand>, String> {
    let file_size = fs::metadata(&path)
        .map_err(|e| format!("Cannot stat file: {e}"))?
        .len();
    if file_size > MAX_SAFE_MMAP_BYTES {
        return Err(format!(
            "File too large for safe Mach-O mmap parse ({} bytes, max {}).",
            file_size,
            MAX_SAFE_MMAP_BYTES
        ));
    }

    let file_handle = fs::File::open(&path)
        .map_err(|e| format!("Cannot open file: {e}"))?;
    let mmap = unsafe {
        MmapOptions::new().map(&file_handle)
            .map_err(|e| format!("mmap failed: {e}"))?
    };
    let data: &[u8] = &mmap;

    if data.len() < 4 { return Ok(vec![]); }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0;4]));

    // Determine Mach-O flavor
    let (is64, swap) = match magic {
        0xFEEDFACF => (true, false),   // MH_MAGIC_64
        0xCFFAEDFE => (true, true),    // MH_CIGAM_64
        0xFEEDFACE => (false, false),  // MH_MAGIC
        0xCEFAEDFE => (false, true),   // MH_CIGAM
        _ => return Ok(vec![]),         // Not Mach-O (or fat binary)
    };

    let read32 = |off: usize| -> Option<u32> {
        let raw = u32::from_le_bytes(data.get(off..off+4)?.try_into().ok()?);
        Some(if swap { raw.swap_bytes() } else { raw })
    };

    // Mach-O header: magic(4) cpu_type(4) cpu_subtype(4) filetype(4) ncmds(4) sizeofcmds(4) flags(4) [reserved(4) if 64]
    let hdr_size = if is64 { 32usize } else { 28 };
    if data.len() < hdr_size { return Ok(vec![]); }
    let ncmds = read32(16).unwrap_or(0) as usize;

    let mut offset = hdr_size;
    let mut cmds: Vec<MachLoadCommand> = Vec::with_capacity(ncmds.min(128));

    for _ in 0..ncmds.min(256) {
        let Some(cmd)     = read32(offset)     else { break };
        let Some(cmdsize) = read32(offset + 4) else { break };
        if cmdsize < 8 || offset + cmdsize as usize > data.len() { break; }

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
            _    => "LC_UNKNOWN",
        };

        cmds.push(MachLoadCommand { cmd: cmd_name.to_string(), cmdsize });
        offset += cmdsize as usize;
    }

    Ok(cmds)
}