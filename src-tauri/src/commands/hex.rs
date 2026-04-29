use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, serde::Serialize)]
pub struct StringMatch {
    pub offset: u64,
    pub length: usize,
    pub text: String,
}

/// Returns the total size of `path` in bytes without reading its contents.
#[tauri::command]
pub fn get_file_size(path: String) -> Result<u64, String> {
    let meta = std::fs::metadata(&path).map_err(|e| format!("Failed to stat file: {}", e))?;
    Ok(meta.len())
}

/// Read `length` bytes from `path` starting at `offset`.
/// Uses seek-based I/O — no full-file read, works for files of any size.
#[tauri::command]
pub fn read_hex_range(path: String, offset: u64, length: usize) -> Result<Vec<u8>, String> {
    let mut file = File::open(&path).map_err(|e| format!("Failed to open file: {}", e))?;
    let file_len = file
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("Failed to seek to end: {}", e))?;

    if offset >= file_len {
        return Ok(vec![]);
    }

    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to offset: {}", e))?;

    let to_read = ((file_len - offset) as usize).min(length);
    let mut buf = vec![0u8; to_read];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read bytes: {}", e))?;

    Ok(buf)
}

#[tauri::command]
#[allow(non_snake_case)]
pub fn find_strings(path: String, offset: usize, length: usize, minLength: usize) -> Result<Vec<StringMatch>, String> {
    let min_length = minLength;
    let mut file = File::open(&path).map_err(|e| format!("Failed to open file: {}", e))?;
    let file_len = file
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("Failed to seek: {}", e))? as usize;

    let start = offset.min(file_len);
    let end   = (offset + length).min(file_len);
    if start >= end {
        return Ok(vec![]);
    }

    file.seek(SeekFrom::Start(start as u64))
        .map_err(|e| format!("Failed to seek to offset: {}", e))?;

    let to_read = end - start;
    let mut data = vec![0u8; to_read];
    file.read_exact(&mut data)
        .map_err(|e| format!("Failed to read bytes: {}", e))?;

    Ok(find_strings_in_bytes(&data, min_length, start as u64))
}

fn find_strings_in_bytes(bytes: &[u8], min_length: usize, base_offset: u64) -> Vec<StringMatch> {
    let mut matches = Vec::new();
    let mut current_start = None;
    let mut current_run = Vec::new();
    let mut pos = 0;

    while pos < bytes.len() {
        let byte = bytes[pos];
        let run_length = if byte == 0x09 || byte == 0x0A || byte == 0x0D || (0x20..=0x7E).contains(&byte) {
            1
        } else if (0xC2..=0xDF).contains(&byte) {
            2
        } else if (0xE0..=0xEF).contains(&byte) {
            3
        } else if (0xF0..=0xF4).contains(&byte) {
            4
        } else {
            0
        };

        if run_length == 0 || pos + run_length > bytes.len() {
            if let Some(start) = current_start {
                if current_run.len() >= min_length {
                    if let Ok(text) = std::str::from_utf8(&current_run) {
                        if text.chars().all(|c| c == '\t' || c == '\n' || c == '\r' || !c.is_control()) {
                            matches.push(StringMatch {
                                offset: base_offset + start as u64,
                                length: current_run.len(),
                                text: text.to_string(),
                            });
                        }
                    }
                }
            }
            current_start = None;
            current_run.clear();
            pos += 1;
            continue;
        }

        if run_length > 1 {
            let segment = &bytes[pos..pos + run_length];
            let valid_continuation = segment.iter().skip(1).all(|b| (0x80..=0xBF).contains(b));
            if !valid_continuation {
                if let Some(start) = current_start {
                    if current_run.len() >= min_length {
                        if let Ok(text) = std::str::from_utf8(&current_run) {
                            if text.chars().all(|c| c == '\t' || c == '\n' || c == '\r' || !c.is_control()) {
                                matches.push(StringMatch {
                                    offset: base_offset + start as u64,
                                    length: current_run.len(),
                                    text: text.to_string(),
                                });
                            }
                        }
                    }
                }
                current_start = None;
                current_run.clear();
                pos += 1;
                continue;
            }
        }

        if current_start.is_none() {
            current_start = Some(pos);
        }
        current_run.extend_from_slice(&bytes[pos..pos + run_length]);
        pos += run_length;
    }

    if let Some(start) = current_start {
        if current_run.len() >= min_length {
            if let Ok(text) = std::str::from_utf8(&current_run) {
                if text.chars().all(|c| c == '\t' || c == '\n' || c == '\r' || !c.is_control()) {
                    matches.push(StringMatch {
                        offset: base_offset + start as u64,
                        length: current_run.len(),
                        text: text.to_string(),
                    });
                }
            }
        }
    }

    matches
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_hex_range_returns_requested_slice() {
        let tmp = tempfile(b"ABCDEFGHIJ");
        let result = read_hex_range(tmp.path().to_string_lossy().into_owned(), 2, 4).unwrap();
        assert_eq!(result, b"CDEF");
    }

    #[test]
    fn read_hex_range_clamps_to_file_end() {
        let tmp = tempfile(b"HELLO");
        let result = read_hex_range(tmp.path().to_string_lossy().into_owned(), 3, 100).unwrap();
        assert_eq!(result, b"LO");
    }

    #[test]
    fn read_hex_range_out_of_bounds_returns_empty() {
        let tmp = tempfile(b"HELLO");
        let result = read_hex_range(tmp.path().to_string_lossy().into_owned(), 100, 10).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn find_strings_in_bytes_finds_ascii() {
        let data = b"\x00\x00Hello World\x00\x00";
        let matches = find_strings_in_bytes(data, 4, 0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].text, "Hello World");
    }

    #[test]
    fn find_strings_in_bytes_respects_min_length() {
        let data = b"\x00ABC\x00ABCDEFGH\x00";
        let matches = find_strings_in_bytes(data, 5, 0);
        // "ABC" is only 3 chars — should NOT appear
        assert!(!matches.iter().any(|m| m.text == "ABC"));
        // "ABCDEFGH" is 8 chars — should appear
        assert!(matches.iter().any(|m| m.text == "ABCDEFGH"));
    }

    #[test]
    fn find_strings_in_bytes_offset_is_correct() {
        let data = b"\x00\x00\x00Hello\x00";
        let matches = find_strings_in_bytes(data, 4, 100);
        assert_eq!(matches[0].offset, 103); // base 100 + position 3
    }

    #[test]
    fn find_strings_in_bytes_empty_input_returns_empty() {
        let matches = find_strings_in_bytes(b"", 4, 0);
        assert!(matches.is_empty());
    }

    #[test]
    fn find_strings_in_bytes_no_strings_returns_empty() {
        let data = vec![0x00u8, 0x01, 0x02, 0x80, 0xFF];
        let matches = find_strings_in_bytes(&data, 4, 0);
        assert!(matches.is_empty());
    }

    fn tempfile(content: &[u8]) -> TempFile {
        TempFile::new(content)
    }

    /// Minimal temp-file helper that cleans up on drop.
    struct TempFile {
        path: std::path::PathBuf,
    }

    impl TempFile {
        fn new(content: &[u8]) -> Self {
            use std::io::Write;
            let mut path = std::env::temp_dir();
            path.push(format!("hexhawk_test_{}.bin", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()));
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content).unwrap();
            TempFile { path }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
