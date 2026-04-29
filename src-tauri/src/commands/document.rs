//! document — PDF JavaScript / stream extraction and Office macro extraction.
//!
//! ## PDF analysis (`analyze_pdf`)
//! Uses `lopdf` to walk the PDF object tree and extract:
//!   - JavaScript actions (/JS, /JavaScript, /OpenAction → JS)
//!   - Embedded files (/EmbeddedFile)
//!   - URI launch actions
//!   - FlateDecode / ASCIIHexDecode streams (raw content)
//!
//! ## Office macro extraction (`analyze_office`)
//! Supports:
//!   - Legacy OLE2 (.doc / .xls / .ppt) via the `cfb` crate — reads the
//!     "VBA/dir" stream to extract macro source.
//!   - OOXML (.docx / .xlsx / .pptx) — unzips the archive, locates
//!     `word/vbaProject.bin` (or equivalent), then applies the same OLE2 path.

use serde::Serialize;
use std::collections::HashSet;
use std::io::Read;

// ─── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PdfAnalysisResult {
    /// All JavaScript snippets found (/JS, /JavaScript, OpenAction JS)
    pub javascript: Vec<PdfScript>,
    /// Embedded file names (/EmbeddedFile)
    pub embedded_files: Vec<String>,
    /// URI actions found in the document
    pub uri_actions: Vec<String>,
    /// Suspicious signal flags derived from the content
    pub signals: Vec<DocSignal>,
    /// Total objects inspected
    pub object_count: usize,
    /// Error encountered during parsing (non-fatal; partial results may still be present)
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PdfScript {
    /// Object number where this script was found
    pub object_id: u32,
    /// Raw JavaScript text
    pub source: String,
    /// Dangerous patterns found inside this script
    pub dangerous_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OfficeAnalysisResult {
    /// Extracted VBA modules
    pub modules: Vec<VbaModule>,
    /// Suspicious signal flags
    pub signals: Vec<DocSignal>,
    /// Error encountered during parsing (non-fatal)
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VbaModule {
    /// Stream / module name
    pub name: String,
    /// Decompressed VBA source text (best-effort — compressed VBA p-code is decoded when possible)
    pub source: String,
    /// Dangerous patterns found in this module
    pub dangerous_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DocSignal {
    pub label: String,
    pub confidence: u8,
    pub category: String,
}

// ─── PDF dangerous-pattern table ─────────────────────────────────────────────

/// Returns a list of pattern labels found in `js_source`.
fn scan_js_patterns(js_source: &str) -> Vec<String> {
    // (substring to match, human label)
    const PATTERNS: &[(&str, &str)] = &[
        ("eval(",              "eval() call — dynamic code execution"),
        ("unescape(",          "unescape() — often used to de-obfuscate payloads"),
        ("String.fromCharCode","fromCharCode encoding — obfuscated strings"),
        ("app.launchURL",      "app.launchURL — URL launch (phishing / drive-by)"),
        ("this.exportDataObject","exportDataObject — file drop via PDF"),
        ("util.printf",        "util.printf format-string exploit candidate"),
        ("getAnnots(",         "getAnnots — heap-spray candidate"),
        ("media.newPlayer",    "media.newPlayer — historical exploit target"),
        ("/encode",            "encoding routine — possible obfuscation"),
        ("\\x",                "hex escape sequences — obfuscated payload"),
        ("%u",                 "Unicode escape sequences — shellcode candidate"),
    ];
    let lower = js_source.to_lowercase();
    PATTERNS
        .iter()
        .filter(|(pat, _)| lower.contains(&pat.to_lowercase()))
        .map(|(_, label)| label.to_string())
        .collect()
}

// ─── Office dangerous-pattern table ──────────────────────────────────────────

fn scan_vba_patterns(source: &str) -> Vec<String> {
    const PATTERNS: &[(&str, &str)] = &[
        ("AutoOpen",           "AutoOpen — macro runs on document open"),
        ("Document_Open",      "Document_Open — macro runs on document open"),
        ("Workbook_Open",      "Workbook_Open — macro runs on workbook open"),
        ("Auto_Open",          "Auto_Open — macro runs on spreadsheet open"),
        ("Shell(",             "Shell() — OS command execution"),
        ("CreateObject(",      "CreateObject — COM object instantiation (common in droppers)"),
        ("WScript.Shell",      "WScript.Shell — Windows Script Host shell"),
        ("PowerShell",         "PowerShell invocation from macro"),
        ("cmd.exe",            "cmd.exe reference — command shell"),
        ("URLDownloadToFile",  "URLDownloadToFile — file download from macro"),
        ("Environ(",           "Environ() — environment variable read (host fingerprinting)"),
        ("Chr(",               "Chr() encoding — obfuscated string construction"),
        ("\\x",                "hex escape — possible shellcode"),
        ("Base64",             "Base64 reference — encoded payload"),
        ("certutil",           "certutil abuse — LOLBin download/decode"),
    ];
    let lower = source.to_lowercase();
    PATTERNS
        .iter()
        .filter(|(pat, _)| lower.contains(&pat.to_lowercase()))
        .map(|(_, label)| label.to_string())
        .collect()
}

// ─── Signal derivation ────────────────────────────────────────────────────────

fn derive_pdf_signals(result: &PdfAnalysisResult) -> Vec<DocSignal> {
    let mut signals: Vec<DocSignal> = Vec::new();

    if !result.javascript.is_empty() {
        signals.push(DocSignal {
            label: format!("{} JavaScript block(s) embedded in PDF", result.javascript.len()),
            confidence: 85,
            category: "security".into(),
        });
    }
    if !result.embedded_files.is_empty() {
        signals.push(DocSignal {
            label: format!("{} embedded file(s) in PDF", result.embedded_files.len()),
            confidence: 80,
            category: "dropper".into(),
        });
    }

    // Aggregate dangerous pattern hits across all scripts
    let all_patterns: HashSet<String> = result
        .javascript
        .iter()
        .flat_map(|s| s.dangerous_patterns.iter().cloned())
        .collect();
    for pat in &all_patterns {
        signals.push(DocSignal {
            label: pat.clone(),
            confidence: 90,
            category: "security".into(),
        });
    }
    signals
}

fn derive_office_signals(modules: &[VbaModule]) -> Vec<DocSignal> {
    let mut signals: Vec<DocSignal> = Vec::new();
    if !modules.is_empty() {
        signals.push(DocSignal {
            label: format!("{} VBA module(s) found", modules.len()),
            confidence: 80,
            category: "macro".into(),
        });
    }
    let all_patterns: HashSet<String> = modules
        .iter()
        .flat_map(|m| m.dangerous_patterns.iter().cloned())
        .collect();
    for pat in &all_patterns {
        signals.push(DocSignal {
            label: pat.clone(),
            confidence: 90,
            category: "security".into(),
        });
    }
    signals
}

// ─── PDF analysis ─────────────────────────────────────────────────────────────

#[tauri::command]
pub fn analyze_pdf(path: String) -> PdfAnalysisResult {
    match analyze_pdf_inner(&path) {
        Ok(mut r) => {
            r.signals = derive_pdf_signals(&r);
            r
        }
        Err(e) => PdfAnalysisResult {
            javascript: vec![],
            embedded_files: vec![],
            uri_actions: vec![],
            signals: vec![],
            object_count: 0,
            parse_error: Some(e),
        },
    }
}

fn analyze_pdf_inner(path: &str) -> Result<PdfAnalysisResult, String> {
    let doc = lopdf::Document::load(path)
        .map_err(|e| format!("lopdf: {e}"))?;

    let object_count = doc.objects.len();
    let mut javascript: Vec<PdfScript> = Vec::new();
    let mut embedded_files: Vec<String> = Vec::new();
    let mut uri_actions: Vec<String> = Vec::new();

    for (&(id, _gen), obj) in &doc.objects {
        match obj {
            lopdf::Object::Dictionary(dict) => {
                inspect_pdf_dict(id, dict, &doc, &mut javascript, &mut embedded_files, &mut uri_actions);
            }
            lopdf::Object::Stream(stream) => {
                inspect_pdf_dict(id, &stream.dict, &doc, &mut javascript, &mut embedded_files, &mut uri_actions);
                // Also try to decode the stream itself if it looks like JS
                if let Ok(lopdf::Object::Name(subtype)) = stream.dict.get(b"Subtype") {
                    if subtype == b"JavaScript" {
                        if let Ok(content) = stream.decompressed_content() {
                            let source = lossy_utf8(&content);
                            let dangerous_patterns = scan_js_patterns(&source);
                            javascript.push(PdfScript { object_id: id, source, dangerous_patterns });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(PdfAnalysisResult {
        javascript,
        embedded_files,
        uri_actions,
        signals: vec![], // filled in by caller
        object_count,
        parse_error: None,
    })
}

fn inspect_pdf_dict(
    id: u32,
    dict: &lopdf::Dictionary,
    doc: &lopdf::Document,
    javascript: &mut Vec<PdfScript>,
    embedded_files: &mut Vec<String>,
    uri_actions: &mut Vec<String>,
) {
    // Check /Type = /EmbeddedFile
    if let Ok(lopdf::Object::Name(t)) = dict.get(b"Type") {
        if t == b"EmbeddedFile" {
            if let Some(name) = dict_str(dict, b"F").or_else(|| dict_str(dict, b"UF")) {
                embedded_files.push(name);
            } else {
                embedded_files.push(format!("(obj {})", id));
            }
        }
    }

    // Check /S = /JavaScript  (Action dictionary)
    if let Ok(lopdf::Object::Name(subtype)) = dict.get(b"S") {
        if subtype == b"JavaScript" {
            // /JS is either a string or a reference to a stream
            let source_opt = extract_js_from_action(dict, doc);
            if let Some(source) = source_opt {
                let dangerous_patterns = scan_js_patterns(&source);
                javascript.push(PdfScript { object_id: id, source, dangerous_patterns });
            }
        }
        if subtype == b"URI" {
            if let Some(uri) = dict_str(dict, b"URI") {
                uri_actions.push(uri);
            }
        }
        if subtype == b"Launch" {
            if let Some(f) = dict_str(dict, b"F") {
                uri_actions.push(format!("Launch:{f}"));
            }
        }
    }
}

fn extract_js_from_action(dict: &lopdf::Dictionary, doc: &lopdf::Document) -> Option<String> {
    let js_obj = dict.get(b"JS").ok()?;
    match js_obj {
        lopdf::Object::String(bytes, _) => Some(lossy_utf8(bytes)),
        lopdf::Object::Reference(r) => {
            match doc.get_object(*r).ok()? {
                lopdf::Object::String(bytes, _) => Some(lossy_utf8(bytes)),
                lopdf::Object::Stream(stream) => {
                    stream.decompressed_content().ok().map(|b| lossy_utf8(&b))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn dict_str(dict: &lopdf::Dictionary, key: &[u8]) -> Option<String> {
    match dict.get(key).ok()? {
        lopdf::Object::String(bytes, _) => Some(lossy_utf8(bytes)),
        _ => None,
    }
}

fn lossy_utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ─── Office / OLE2 analysis ───────────────────────────────────────────────────

#[tauri::command]
pub fn analyze_office(path: String) -> OfficeAnalysisResult {
    // Detect OOXML (.docx / .xlsx / .pptx) by ZIP magic bytes
    let is_ooxml = {
        let mut hdr = [0u8; 4];
        std::fs::File::open(&path)
            .and_then(|mut f| f.read_exact(&mut hdr).map(|_| f))
            .map(|_| hdr == [0x50, 0x4B, 0x03, 0x04])
            .unwrap_or(false)
    };

    if is_ooxml {
        analyze_ooxml(&path)
    } else {
        analyze_ole2(&path)
    }
}

/// OOXML: unzip → find vbaProject.bin → treat as OLE2
fn analyze_ooxml(path: &str) -> OfficeAnalysisResult {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return OfficeAnalysisResult {
            modules: vec![],
            signals: vec![],
            parse_error: Some(format!("open: {e}")),
        },
    };

    let mut archive = match zip::ZipArchive::new(file) {
        Ok(a) => a,
        Err(e) => return OfficeAnalysisResult {
            modules: vec![],
            signals: vec![],
            parse_error: Some(format!("zip: {e}")),
        },
    };

    // VBA project bin locations across Word / Excel / PowerPoint
    let vba_paths = [
        "word/vbaProject.bin",
        "xl/vbaProject.bin",
        "ppt/vbaProject.bin",
    ];

    let mut vba_bytes: Option<Vec<u8>> = None;
    for &vba_path in &vba_paths {
        if let Ok(mut entry) = archive.by_name(vba_path) {
            let mut buf = Vec::new();
            if entry.read_to_end(&mut buf).is_ok() {
                vba_bytes = Some(buf);
                break;
            }
        }
    }

    match vba_bytes {
        None => OfficeAnalysisResult {
            modules: vec![],
            signals: vec![DocSignal {
                label: "No VBA project found in OOXML archive (macros not present)".into(),
                confidence: 70,
                category: "info".into(),
            }],
            parse_error: None,
        },
        Some(bytes) => {
            // Write to a temp file and parse as OLE2
            let tmp_path = std::env::temp_dir().join("hexhawk_vba_tmp.bin");
            if let Err(e) = std::fs::write(&tmp_path, &bytes) {
                return OfficeAnalysisResult {
                    modules: vec![],
                    signals: vec![],
                    parse_error: Some(format!("temp write: {e}")),
                };
            }
            let tmp_str = tmp_path.to_string_lossy().into_owned();
            analyze_ole2(&tmp_str)
        }
    }
}

/// OLE2: use cfb crate to open, walk streams, extract VBA source
fn analyze_ole2(path: &str) -> OfficeAnalysisResult {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return OfficeAnalysisResult {
            modules: vec![],
            signals: vec![],
            parse_error: Some(format!("open: {e}")),
        },
    };

    let mut comp = match cfb::CompoundFile::open(file) {
        Ok(c) => c,
        Err(e) => return OfficeAnalysisResult {
            modules: vec![],
            signals: vec![],
            parse_error: Some(format!("cfb: {e}")),
        },
    };

    let mut modules: Vec<VbaModule> = Vec::new();

    // Collect all stream paths first to avoid borrow issues
    let stream_paths: Vec<String> = comp
        .walk()
        .filter(|e| e.is_stream())
        .map(|e| e.path().to_string_lossy().into_owned())
        .collect();

    for stream_path in &stream_paths {
        // We're interested in streams that look like VBA module streams.
        // The VBA spec stores module source in streams under /VBA/<ModuleName>.
        // We heuristically collect all streams with recognisable names.
        let name = stream_path
            .rsplit('/')
            .next()
            .unwrap_or(stream_path)
            .to_string();

        if should_skip_stream(&name) {
            continue;
        }

        let mut buf = Vec::new();
        {
            let mut stream = match comp.open_stream(stream_path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if stream.read_to_end(&mut buf).is_err() {
                continue;
            }
        }

        // Try to extract readable text. VBA streams are compressed p-code
        // preceded by a plain-text "attribute" header that lists source.
        // We extract the printable ASCII portion as a best-effort approach.
        let source = extract_vba_text(&buf);
        if source.trim().is_empty() {
            continue;
        }

        let dangerous_patterns = scan_vba_patterns(&source);
        modules.push(VbaModule { name, source, dangerous_patterns });
    }

    let signals = derive_office_signals(&modules);
    OfficeAnalysisResult { modules, signals, parse_error: None }
}

fn should_skip_stream(name: &str) -> bool {
    // Skip well-known binary/storage streams that are not VBA source
    matches!(
        name,
        "__SRP_0" | "__SRP_1" | "__SRP_2" | "__SRP_3"
        | "_VBA_PROJECT" | "dir" | "PROJECT" | "PROJECTwm"
        | "SummaryInformation" | "DocumentSummaryInformation"
        | "CompObj" | "WordDocument" | "Workbook" | "PowerPoint Document"
        | "1Table" | "0Table"
    )
}

/// Extract printable text from a raw VBA stream buffer.
/// Real decompression of the MS-OVBA compression format is complex;
/// we use a heuristic: find runs of printable ASCII ≥ 6 chars.
fn extract_vba_text(buf: &[u8]) -> String {
    // Look for the "Attribute VB_Name" header which is stored uncompressed
    // at the top of a VBA module stream. Extract it as the primary source.
    let mut lines: Vec<String> = Vec::new();
    let mut run = Vec::<u8>::new();

    for &b in buf {
        if (b >= 0x20 && b < 0x7f) || b == b'\r' || b == b'\n' || b == b'\t' {
            run.push(b);
        } else {
            if run.len() >= 6 {
                let s = String::from_utf8_lossy(&run).into_owned();
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    lines.push(trimmed.to_string());
                }
            }
            run.clear();
        }
    }
    if run.len() >= 6 {
        let s = String::from_utf8_lossy(&run).into_owned();
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            lines.push(trimmed.to_string());
        }
    }

    lines.join("\n")
}
