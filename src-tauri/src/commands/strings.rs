//! strings — extract printable ASCII + UTF-16LE strings from any file.
//!
//! Works on any format (PE, ELF, PDF, scripts, archives, PCAP) without
//! needing a successful object parse.  For files > 64 MB only the first
//! 60 MB and last 4 MB are scanned to cap wall-time on huge binaries like
//! 10000.exe while still finding the actual code/data at the end.

use serde::Serialize;
use std::fs;
use std::io::{Read, Seek, SeekFrom};

// ── Output types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedStrings {
    /// ASCII printable strings (min 4 chars)
    pub ascii: Vec<String>,
    /// UTF-16LE strings (min 4 chars, common in Windows binaries)
    pub unicode: Vec<String>,
    /// URLs found in strings (http/https/ftp/C2 patterns)
    pub urls: Vec<String>,
    /// File system + registry paths
    pub paths: Vec<String>,
    /// API-name-looking identifiers (PascalCase ≤ 64 chars)
    pub api_names: Vec<String>,
    /// Total unique strings found
    pub total: usize,
    /// Bytes scanned (may be less than file_size for large files)
    pub bytes_scanned: u64,
    /// Actual file size
    pub file_size: u64,
    /// Format hint from magic bytes
    pub format_hint: String,
}

// ── Public entry point ────────────────────────────────────────────────────────

pub fn extract_strings(path: String) -> Result<ExtractedStrings, String> {
    const SCAN_LIMIT: u64 = 64 * 1024 * 1024;  // 64 MB max scan
    const TAIL_SIZE:  u64 = 4 * 1024 * 1024;   // always scan last 4 MB

    let file_meta = fs::metadata(&path)
        .map_err(|e| format!("stat failed: {e}"))?;
    let file_size = file_meta.len();

    // ── Read bytes to scan ────────────────────────────────────────────────
    let data = if file_size <= SCAN_LIMIT {
        fs::read(&path).map_err(|e| format!("Failed to read: {e}"))?
    } else {
        // Head: first (SCAN_LIMIT - TAIL_SIZE) bytes
        // Tail: last TAIL_SIZE bytes
        let head_size = (SCAN_LIMIT - TAIL_SIZE) as usize;
        let mut buf = vec![0u8; head_size];
        let mut f = fs::File::open(&path)
            .map_err(|e| format!("Failed to open: {e}"))?;
        f.read_exact(&mut buf)
            .map_err(|e| format!("Head read error: {e}"))?;
        f.seek(SeekFrom::End(-(TAIL_SIZE as i64)))
            .map_err(|e| format!("Seek error: {e}"))?;
        let mut tail = vec![0u8; TAIL_SIZE as usize];
        let n = f.read(&mut tail)
            .map_err(|e| format!("Tail read error: {e}"))?;
        buf.extend_from_slice(&tail[..n]);
        buf
    };

    let bytes_scanned = data.len() as u64;

    // Format hint from magic
    let format_hint = detect_magic_hint(&data);

    // ── Extract strings ────────────────────────────────────────────────────
    let ascii   = extract_ascii(&data, 4);
    let unicode = extract_utf16le(&data, 4);

    // ── Categorize ─────────────────────────────────────────────────────────
    let all: Vec<&str> = ascii.iter().chain(unicode.iter()).map(String::as_str).collect();
    let urls      = classify_urls(&all);
    let paths     = classify_paths(&all);
    let api_names = classify_api_names(&all);
    let total     = ascii.len() + unicode.len();

    Ok(ExtractedStrings {
        ascii,
        unicode,
        urls,
        paths,
        api_names,
        total,
        bytes_scanned,
        file_size,
        format_hint,
    })
}

// ── ASCII string extraction ───────────────────────────────────────────────────

fn extract_ascii(data: &[u8], min_len: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for &b in data {
        if b >= 0x20 && b < 0x7f {
            current.push(b);
        } else {
            if current.len() >= min_len {
                result.push(String::from_utf8_lossy(&current).into_owned());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        result.push(String::from_utf8_lossy(&current).into_owned());
    }
    result
}

// ── UTF-16LE string extraction ────────────────────────────────────────────────
// Slides by 1 byte at a time to handle misaligned strings.

fn extract_utf16le(data: &[u8], min_len: usize) -> Vec<String> {
    if data.len() < 4 { return vec![]; }
    let mut result = Vec::new();
    let mut current: Vec<u16> = Vec::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);
        if word >= 0x0020 && word < 0x007f {
            current.push(word);
            i += 2;
        } else {
            if current.len() >= min_len {
                if let Ok(s) = String::from_utf16(&current) {
                    result.push(s);
                }
            }
            current.clear();
            i += 1;
        }
    }
    if current.len() >= min_len {
        if let Ok(s) = String::from_utf16(&current) {
            result.push(s);
        }
    }
    result
}

// ── Classification helpers ────────────────────────────────────────────────────

fn classify_urls(strings: &[&str]) -> Vec<String> {
    strings.iter()
        .filter(|s| {
            s.contains("http://") || s.contains("https://") ||
            s.contains("ftp://")  || s.contains("tcp://")   ||
            s.contains("://")
        })
        .map(|s| s.to_string())
        .collect()
}

fn classify_paths(strings: &[&str]) -> Vec<String> {
    strings.iter()
        .filter(|s| {
            s.starts_with("C:\\") || s.starts_with("c:\\")  ||
            s.starts_with("\\\\")                            ||
            s.contains("\\System32\\") || s.contains("\\Windows\\") ||
            s.contains("\\Temp\\")     || s.contains("\\AppData\\") ||
            s.starts_with("HKEY_")     || s.starts_with("HKCU")     ||
            s.starts_with("HKLM")      || s.starts_with("SOFTWARE\\") ||
            s.starts_with("/etc/")     || s.starts_with("/proc/")   ||
            s.starts_with("/tmp/")     || s.starts_with("/dev/")    ||
            s.ends_with(".exe")        || s.ends_with(".dll")       ||
            s.ends_with(".sys")        || s.ends_with(".bat")       ||
            s.ends_with(".ps1")        || s.ends_with(".vbs")
        })
        .map(|s| s.to_string())
        .collect()
}

fn classify_api_names(strings: &[&str]) -> Vec<String> {
    // Heuristic: PascalCase, ASCII-only, len 4..=64, no spaces
    strings.iter()
        .filter(|s| {
            let bytes = s.as_bytes();
            let len = bytes.len();
            len >= 4 && len <= 64 &&
            bytes[0].is_ascii_uppercase() &&
            bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') &&
            // Require at least one lowercase letter (avoids all-caps constants)
            bytes.iter().any(|b| b.is_ascii_lowercase())
        })
        .map(|s| s.to_string())
        .collect()
}

// ── Magic hint ────────────────────────────────────────────────────────────────

fn detect_magic_hint(data: &[u8]) -> String {
    match data {
        [0x4D, 0x5A, ..]                   => "PE/MZ".into(),
        [0x7F, 0x45, 0x4C, 0x46, ..]       => "ELF".into(),
        [0xCF, 0xFA, 0xED, 0xFE, ..]
        | [0xCE, 0xFA, 0xED, 0xFE, ..]
        | [0xCA, 0xFE, 0xBA, 0xBE, ..]     => "Mach-O".into(),
        [0x25, 0x50, 0x44, 0x46, ..]       => "PDF".into(),
        [0x50, 0x4B, 0x03, 0x04, ..]
        | [0x50, 0x4B, 0x05, 0x06, ..]     => "ZIP".into(),
        [0x52, 0x61, 0x72, 0x21, 0x1A, ..] => "RAR".into(),
        [0x37, 0x7A, 0xBC, 0xAF, 0x27, ..] => "7-Zip".into(),
        [0x1F, 0x8B, ..]                   => "GZip".into(),
        [0x23, 0x21, ..]                   => "Script/shebang".into(),
        [0x0A, 0x0D, 0x0D, 0x0A, ..]       => "PCAPNG".into(),
        [0xD4, 0xC3, 0xB2, 0xA1, ..]
        | [0xA1, 0xB2, 0xC3, 0xD4, ..]     => "PCAP".into(),
        _                                  => {
            // Check if it looks like a text file (first 512 bytes printable)
            let sample = &data[..std::cmp::min(512, data.len())];
            if sample.iter().all(|&b| b >= 0x09 && b < 0x80) {
                "Text/Script".into()
            } else {
                let magic = data.get(..4).map(|b| {
                    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
                }).unwrap_or_else(|| "??".into());
                format!("Unknown [magic: {magic}]")
            }
        }
    }
}
