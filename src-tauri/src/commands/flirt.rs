//! FLIRT signature (.sig / .pat) parser and binary function-name matcher.
//!
//! Supports:
//!   - IDA FLAIR .sig binary format (versions 6–9, prefix-trie compressed)
//!   - FLAIR .pat text format (line-based, fully documented)
//!
//! Usage (Tauri IPC):
//!   `inspect_sig_file(sig_path)`           → library metadata
//!   `match_flirt_signatures(binary_path, sig_path)` → matched function names

use serde::{Deserialize, Serialize};
use std::fs;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default pattern size (bytes) for FLIRT patterns.
const DEFAULT_PATTERN_SIZE: usize = 32;

/// Minimum ASCII string length to consider as a library function name.
const MIN_FUNC_NAME_LEN: usize = 2;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct FlirtLibInfo {
    pub format: String,
    pub version: Option<u8>,
    pub arch: Option<u8>,
    pub library_name: String,
    pub n_functions: u32,
    pub pattern_size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlirtMatch {
    /// Virtual or file offset where the pattern matched.
    pub offset: u64,
    /// Matched function name(s).
    pub names: Vec<FlirtMatchName>,
    /// CRC16 verification passed (or n/a when crc_len == 0).
    pub crc_ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlirtMatchName {
    /// Byte offset relative to pattern start.
    pub func_offset: u32,
    pub name: String,
    pub is_local: bool,
}

#[derive(Debug, Serialize)]
pub struct FlirtMatchResult {
    pub library_name: String,
    pub format: String,
    pub patterns_loaded: usize,
    pub binary_bytes_scanned: u64,
    pub matches: Vec<FlirtMatch>,
}

// ── Internal pattern representation ──────────────────────────────────────────

#[derive(Debug, Clone)]
struct FlirtPattern {
    /// Pattern bytes; None = wildcard.
    bytes: Vec<Option<u8>>,
    /// How many bytes after the pattern to CRC-check (0 = skip).
    crc_len: u8,
    /// Expected CRC16 of those bytes.
    crc16: u16,
    /// Total function length (informational).
    total_len: u32,
    /// One or more named symbols at relative offsets within the pattern area.
    names: Vec<FlirtPatternName>,
}

#[derive(Debug, Clone)]
struct FlirtPatternName {
    func_offset: u32,
    name: String,
    is_local: bool,
}

// ── CRC-16 (CCITT / IBM variant used by FLAIR) ────────────────────────────────

fn crc16_flair(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ── Variable-length integer decoder (FLAIR VLI) ───────────────────────────────

fn read_vli(data: &[u8]) -> Option<(u32, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        // 7-bit
        Some((first as u32, 1))
    } else if first & 0xC0 == 0x80 {
        // 14-bit
        let second = *data.get(1)?;
        let val = (((first & 0x3F) as u32) << 8) | (second as u32);
        Some((val, 2))
    } else if first & 0xE0 == 0xC0 {
        // 21-bit
        let second = *data.get(1)?;
        let third = *data.get(2)?;
        let val = (((first & 0x1F) as u32) << 16)
            | ((second as u32) << 8)
            | (third as u32);
        Some((val, 3))
    } else if first & 0xF0 == 0xE0 {
        // 28-bit
        let second = *data.get(1)?;
        let third = *data.get(2)?;
        let fourth = *data.get(3)?;
        let val = (((first & 0x0F) as u32) << 24)
            | ((second as u32) << 16)
            | ((third as u32) << 8)
            | (fourth as u32);
        Some((val, 4))
    } else {
        // 32-bit: next 4 bytes are the value
        if data.len() < 5 { return None; }
        let val = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        Some((val, 5))
    }
}

// ── Null-terminated string reader ─────────────────────────────────────────────

fn read_cstr(data: &[u8]) -> Option<(&str, usize)> {
    let end = data.iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&data[..end]).ok()?;
    Some((s, end + 1))
}

// ── .sig header parser ────────────────────────────────────────────────────────

#[derive(Debug)]
struct SigHeader {
    version: u8,
    arch: u8,
    file_types: u32,
    os_types: u16,
    app_types: u16,
    features: u16,
    n_functions: u32,
    pattern_size: usize,
    library_name: String,
    /// Byte offset into the file where the tree data starts.
    tree_offset: usize,
}

fn parse_sig_header(data: &[u8]) -> Result<SigHeader, String> {
    // Magic check: "IDASGN" (FLAIR) or "IDASIG" (older)
    if data.len() < 6 {
        return Err("File too small to be a .sig".into());
    }
    let magic = &data[0..6];
    if magic != b"IDASGN" && magic != b"IDASIG" {
        return Err(format!("Not a FLAIR .sig file (magic: {:?})", magic));
    }

    let mut pos = 6usize;

    macro_rules! read_u8 {
        () => {{
            let v = *data.get(pos).ok_or("Unexpected EOF (u8)")?;
            pos += 1;
            v
        }};
    }
    macro_rules! read_u16le {
        () => {{
            let bytes = data.get(pos..pos + 2).ok_or("Unexpected EOF (u16)")?;
            pos += 2;
            u16::from_le_bytes([bytes[0], bytes[1]])
        }};
    }
    macro_rules! read_u32le {
        () => {{
            let bytes = data.get(pos..pos + 4).ok_or("Unexpected EOF (u32)")?;
            pos += 4;
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }};
    }

    let version = read_u8!();
    if version < 6 || version > 10 {
        return Err(format!("Unsupported .sig version: {version}"));
    }

    let arch = read_u8!();
    let file_types = read_u32le!();
    let os_types = read_u16le!();
    let app_types = read_u16le!();
    let features = read_u16le!();
    let old_n_functions = read_u16le!();
    let _crc16 = read_u16le!();
    // ctype[12]
    if data.get(pos..pos + 12).is_none() { return Err("EOF at ctype".into()); }
    pos += 12;
    let lib_name_len = read_u8!() as usize;
    let _ctypes_crc16 = read_u16le!();

    let n_functions: u32 = if version >= 8 {
        read_u32le!()
    } else {
        old_n_functions as u32
    };

    let pattern_size: usize = if version >= 9 {
        let ps = read_u16le!() as usize;
        if ps == 0 { DEFAULT_PATTERN_SIZE } else { ps }
    } else {
        DEFAULT_PATTERN_SIZE
    };

    // Library name
    let lib_name_bytes = data
        .get(pos..pos + lib_name_len)
        .ok_or("EOF at library_name")?;
    let library_name = String::from_utf8_lossy(lib_name_bytes).to_string();
    pos += lib_name_len;

    Ok(SigHeader {
        version,
        arch,
        file_types,
        os_types,
        app_types,
        features,
        n_functions,
        pattern_size,
        library_name,
        tree_offset: pos,
    })
}

// ── .sig tree walker (recursive, depth-first, best-effort) ───────────────────

struct TreeWalker<'a> {
    data: &'a [u8],
    pos: usize,
    pattern_size: usize,
}

impl<'a> TreeWalker<'a> {
    fn new(data: &'a [u8], pattern_size: usize) -> Self {
        Self { data, pos: 0, pattern_size }
    }

    fn remaining(&self) -> &[u8] {
        &self.data[self.pos..]
    }

    fn read_u8(&mut self) -> Option<u8> {
        let v = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    fn read_u16le(&mut self) -> Option<u16> {
        let bytes = self.data.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_vli(&mut self) -> Option<u32> {
        let (val, consumed) = read_vli(&self.data[self.pos..])?;
        self.pos += consumed;
        Some(val)
    }

    fn read_cstr(&mut self) -> Option<String> {
        let (s, consumed) = read_cstr(&self.data[self.pos..])?;
        let owned = s.to_owned();
        self.pos += consumed;
        Some(owned)
    }

    /// Walk the trie from the current position, building up `path` as we descend.
    /// `depth` is the current byte index into the pattern (0-based).
    /// `path` collects the pattern bytes (None = wildcard).
    fn walk(
        &mut self,
        depth: usize,
        path: &mut Vec<Option<u8>>,
        out: &mut Vec<FlirtPattern>,
    ) {
        if depth >= self.pattern_size {
            // Leaf: parse CRC + module list
            if let Some(pat) = self.parse_leaf(path) {
                out.push(pat);
            }
            return;
        }

        // Number of branches at this level
        let n_children = match self.read_u8() {
            Some(v) => v,
            None => return,
        };

        // Guard against malformed files that would blow the stack
        if n_children as usize > 256 {
            return;
        }

        for i in 0..n_children {
            // Each branch has an explicit byte value when there are multiple children.
            // With a single child, the byte is still stored (it's the literal byte at `depth`).
            let child_byte = match self.read_u8() {
                Some(b) => b,
                None => return,
            };

            let pattern_byte: Option<u8> = if child_byte == b'.' { None } else { Some(child_byte) };
            path.push(pattern_byte);

            self.walk(depth + 1, path, out);

            path.pop();

            // Safety: if parsing ran off the end, abort remaining siblings
            if self.pos >= self.data.len() && i + 1 < n_children {
                break;
            }
        }
    }

    /// Parse a leaf node: { crc_len, crc16, [total_len, name records...] }
    fn parse_leaf(&mut self, path: &[Option<u8>]) -> Option<FlirtPattern> {
        let crc_len = self.read_u8()?;
        let crc16 = self.read_u16le()?;
        let total_len = self.read_vli()?;

        let mut names: Vec<FlirtPatternName> = Vec::new();

        // One or more name records; ends when offset VLI == 0 after first iteration
        // or when no valid name follows.
        loop {
            let func_offset = self.read_vli()?;
            let flags = self.read_u8()?;

            let is_local = flags & 0x01 != 0;
            let is_ref   = flags & 0x02 != 0;

            if is_ref {
                // Reference: read ref_delta (vli) + ref_name (cstr) — skip for now
                self.read_vli()?;
                self.read_cstr()?;
            } else {
                let name = self.read_cstr()?;
                if name.len() >= MIN_FUNC_NAME_LEN {
                    names.push(FlirtPatternName { func_offset, name, is_local });
                }
            }

            // Check terminator: if next byte is 0 or next vli is 0, stop
            // (FLAIR convention: multi-name records end with a 0-offset sentinel)
            let peek = self.data.get(self.pos).copied().unwrap_or(0);
            if peek == 0 {
                self.pos += 1; // consume the terminator
                break;
            }
        }

        Some(FlirtPattern {
            bytes: path.to_vec(),
            crc_len,
            crc16,
            total_len,
            names,
        })
    }
}

/// Walk the entire .sig trie and collect all patterns.
fn collect_sig_patterns(tree_data: &[u8], pattern_size: usize) -> Vec<FlirtPattern> {
    let mut walker = TreeWalker::new(tree_data, pattern_size);
    let mut path: Vec<Option<u8>> = Vec::with_capacity(pattern_size);
    let mut out: Vec<FlirtPattern> = Vec::new();
    walker.walk(0, &mut path, &mut out);
    out
}

// ── .pat text format parser ───────────────────────────────────────────────────
//
// Format per line:
//   <hex-pattern> <crc_len(hex2)> <crc16(hex4)> <total_len(hex4)> <name>[@<off>:<name>]*
//
// Where hex-pattern is exactly PATTERN_SIZE * 2 hex chars, with '..' for wildcards.
// Lines starting with '-' are comments/separators.

fn parse_pat_file(text: &str) -> Vec<FlirtPattern> {
    let mut out = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('-') || line.starts_with('#') {
            continue;
        }

        if let Some(pat) = parse_pat_line(line) {
            out.push(pat);
        }
    }

    out
}

fn parse_pat_line(line: &str) -> Option<FlirtPattern> {
    let mut tokens = line.split_whitespace();

    let hex_pat = tokens.next()?;
    let crc_len_hex = tokens.next()?;
    let crc16_hex = tokens.next()?;
    let total_len_hex = tokens.next()?;
    let primary_name = tokens.next()?;

    // Pattern bytes: pairs of hex chars, '..' = wildcard
    if hex_pat.len() < 4 || hex_pat.len() % 2 != 0 {
        return None;
    }

    let mut bytes: Vec<Option<u8>> = Vec::with_capacity(hex_pat.len() / 2);
    let hex_chars: Vec<char> = hex_pat.chars().collect();
    let mut i = 0;
    while i + 1 < hex_chars.len() {
        let hi = hex_chars[i];
        let lo = hex_chars[i + 1];
        if hi == '.' && lo == '.' {
            bytes.push(None);
        } else {
            let val = u8::from_str_radix(&format!("{hi}{lo}"), 16).ok()?;
            bytes.push(Some(val));
        }
        i += 2;
    }

    let crc_len = u8::from_str_radix(crc_len_hex, 16).ok()?;
    let crc16   = u16::from_str_radix(crc16_hex,   16).ok()?;
    let total_len = u32::from_str_radix(total_len_hex, 16).ok()?;

    // Primary name (may have :1 etc. suffix = secondary reference)
    let mut names: Vec<FlirtPatternName> = Vec::new();
    {
        let (offset, name) = split_pat_name_ref(primary_name);
        if name.len() >= MIN_FUNC_NAME_LEN {
            names.push(FlirtPatternName { func_offset: offset, name, is_local: false });
        }
    }

    // Additional names encoded as @<offset>:<name> in remaining tokens
    // (some .pat flavours use this)
    for tok in tokens {
        if let Some(rest) = tok.strip_prefix('@') {
            if let Some(colon) = rest.find(':') {
                let off_hex = &rest[..colon];
                let n = &rest[colon + 1..];
                if let Ok(off) = u32::from_str_radix(off_hex, 16) {
                    if n.len() >= MIN_FUNC_NAME_LEN {
                        names.push(FlirtPatternName {
                            func_offset: off,
                            name: n.to_owned(),
                            is_local: false,
                        });
                    }
                }
            }
        }
    }

    Some(FlirtPattern { bytes, crc_len, crc16, total_len, names })
}

/// Some .pat name fields look like `00 _name` or `01 _name` (local/global prefix).
fn split_pat_name_ref(s: &str) -> (u32, String) {
    // Names sometimes prefixed with hex offset like "00 _func" in flair2pat output.
    // Most commonly the name is just the raw identifier.
    (0, s.to_owned())
}

// ── Binary pattern matcher ─────────────────────────────────────────────────────

fn match_patterns_against_binary(
    binary: &[u8],
    patterns: &[FlirtPattern],
    max_matches: usize,
) -> Vec<FlirtMatch> {
    let mut results: Vec<FlirtMatch> = Vec::new();

    for (offset, window) in binary.windows(DEFAULT_PATTERN_SIZE).enumerate() {
        if results.len() >= max_matches {
            break;
        }
        for pat in patterns {
            if pat.names.is_empty() {
                continue;
            }
            let pat_len = pat.bytes.len().min(window.len());
            if pat_len == 0 {
                continue;
            }

            // Check pattern bytes (with wildcards)
            let mut matched = true;
            for (i, &expected) in pat.bytes[..pat_len].iter().enumerate() {
                if let Some(expected_byte) = expected {
                    if window.get(i).copied().unwrap_or(0) != expected_byte {
                        matched = false;
                        break;
                    }
                }
                // None = wildcard, always matches
            }
            if !matched {
                continue;
            }

            // Optional CRC16 check of bytes immediately after pattern
            let crc_ok = if pat.crc_len == 0 {
                true // no CRC data to verify
            } else {
                let crc_start = offset + pat.bytes.len();
                let crc_end = crc_start + pat.crc_len as usize;
                if let Some(crc_bytes) = binary.get(crc_start..crc_end) {
                    crc16_flair(crc_bytes) == pat.crc16
                } else {
                    false // CRC bytes out of bounds → no match
                }
            };

            if !crc_ok && pat.crc_len > 0 {
                continue;
            }

            let names: Vec<FlirtMatchName> = pat
                .names
                .iter()
                .map(|n| FlirtMatchName {
                    func_offset: n.func_offset,
                    name: n.name.clone(),
                    is_local: n.is_local,
                })
                .collect();

            results.push(FlirtMatch {
                offset: offset as u64,
                names,
                crc_ok,
            });

            // One match per offset (first pattern that matches wins)
            break;
        }
    }

    results
}

// ── File format detection ──────────────────────────────────────────────────────

fn detect_format(data: &[u8]) -> &'static str {
    if data.starts_with(b"IDASGN") || data.starts_with(b"IDASIG") {
        "sig"
    } else {
        "pat"
    }
}

// ── Tauri commands ─────────────────────────────────────────────────────────────

#[tauri::command]
pub fn inspect_sig_file(sig_path: String) -> Result<FlirtLibInfo, String> {
    let data = fs::read(&sig_path).map_err(|e| format!("Cannot read {sig_path}: {e}"))?;

    let format = detect_format(&data);

    if format == "sig" {
        let hdr = parse_sig_header(&data)?;
        Ok(FlirtLibInfo {
            format: "sig".into(),
            version: Some(hdr.version),
            arch: Some(hdr.arch),
            library_name: hdr.library_name,
            n_functions: hdr.n_functions,
            pattern_size: hdr.pattern_size,
        })
    } else {
        // .pat text file — count valid lines
        let text = String::from_utf8_lossy(&data);
        let patterns = parse_pat_file(&text);
        Ok(FlirtLibInfo {
            format: "pat".into(),
            version: None,
            arch: None,
            library_name: sig_path
                .split(['/', '\\'])
                .last()
                .unwrap_or(&sig_path)
                .to_owned(),
            n_functions: patterns.len() as u32,
            pattern_size: if patterns.first().map(|p| p.bytes.len()).unwrap_or(0) > 0 {
                patterns[0].bytes.len()
            } else {
                DEFAULT_PATTERN_SIZE
            },
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct MatchFlirtRequest {
    pub binary_path: String,
    pub sig_path: String,
    /// Maximum number of matches to return (default 4096).
    pub max_matches: Option<usize>,
}

#[tauri::command]
pub fn match_flirt_signatures(request: MatchFlirtRequest) -> Result<FlirtMatchResult, String> {
    let binary = fs::read(&request.binary_path)
        .map_err(|e| format!("Cannot read binary {}: {e}", request.binary_path))?;
    let sig_data = fs::read(&request.sig_path)
        .map_err(|e| format!("Cannot read sig file {}: {e}", request.sig_path))?;

    let max_matches = request.max_matches.unwrap_or(4096).min(65536);
    let format = detect_format(&sig_data);

    let (patterns, library_name, pattern_size) = if format == "sig" {
        let hdr = parse_sig_header(&sig_data)?;
        let tree_data = sig_data
            .get(hdr.tree_offset..)
            .ok_or("SIG tree data missing")?;
        let patterns = collect_sig_patterns(tree_data, hdr.pattern_size);
        let ps = hdr.pattern_size;
        (patterns, hdr.library_name, ps)
    } else {
        let text = String::from_utf8_lossy(&sig_data);
        let patterns = parse_pat_file(&text);
        let lib = request
            .sig_path
            .split(['/', '\\'])
            .last()
            .unwrap_or(&request.sig_path)
            .to_owned();
        (patterns, lib, DEFAULT_PATTERN_SIZE)
    };

    let patterns_loaded = patterns.len();
    let binary_len = binary.len() as u64;

    let matches = match_patterns_against_binary(&binary, &patterns, max_matches);

    Ok(FlirtMatchResult {
        library_name,
        format: format.to_owned(),
        patterns_loaded,
        binary_bytes_scanned: binary_len,
        matches,
    })
}
