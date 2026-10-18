use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub(super) const MAX_HEX_BYTES: usize = 1024 * 1024;
pub(super) const MAX_STRING_SCAN_BYTES: usize = 16 * 1024 * 1024;
const MAX_STRING_RESULTS: usize = 10_000;

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
pub fn read_hex_range(path: String, offset: u64, length: usize) -> Result<Vec<u8>, String> {
    let requested = u64::try_from(length).map_err(|_| "Hex length cannot be represented")?;
    offset.checked_add(requested).ok_or("Hex range overflow")?;
    if length > MAX_HEX_BYTES {
        return Err(format!(
            "Hex byte budget exceeded (maximum {MAX_HEX_BYTES})"
        ));
    }
    let mut file = File::open(&path).map_err(|e| format!("Failed to open file: {}", e))?;
    let file_len = file
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("Failed to seek to end: {}", e))?;

    if offset >= file_len {
        return Ok(vec![]);
    }

    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to offset: {}", e))?;

    let to_read = usize::try_from((file_len - offset).min(requested))
        .map_err(|_| "Hex read length cannot be represented")?;
    let mut buf = vec![0u8; to_read];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read bytes: {}", e))?;

    Ok(buf)
}

#[allow(non_snake_case)]
pub fn find_strings(
    path: String,
    offset: usize,
    length: usize,
    minLength: usize,
) -> Result<Vec<StringMatch>, String> {
    let requested_end = offset
        .checked_add(length)
        .ok_or("String scan range overflow")?;
    if length > MAX_STRING_SCAN_BYTES {
        return Err(format!(
            "String scan byte budget exceeded (maximum {MAX_STRING_SCAN_BYTES})"
        ));
    }
    let min_length = minLength;
    let mut file = File::open(&path).map_err(|e| format!("Failed to open file: {}", e))?;
    let file_len = usize::try_from(
        file.seek(SeekFrom::End(0))
            .map_err(|e| format!("Failed to seek: {}", e))?,
    )
    .map_err(|_| "String scan file size cannot be represented")?;

    let start = offset.min(file_len);
    let end = requested_end.min(file_len);
    if start >= end {
        return Ok(vec![]);
    }

    let start_u64 = u64::try_from(start).map_err(|_| "String scan offset cannot be represented")?;
    file.seek(SeekFrom::Start(start_u64))
        .map_err(|e| format!("Failed to seek to offset: {}", e))?;

    let to_read = end - start;
    let mut data = vec![0u8; to_read];
    file.read_exact(&mut data)
        .map_err(|e| format!("Failed to read bytes: {}", e))?;

    find_strings_in_bytes(&data, min_length, start_u64)
}

// Fail rather than returning an unlabeled partial strings scan.
fn push_string_match(
    matches: &mut Vec<StringMatch>,
    base_offset: u64,
    start: usize,
    text: &str,
) -> Result<(), String> {
    if matches.len() >= MAX_STRING_RESULTS {
        return Err(format!(
            "String result budget exceeded (maximum {MAX_STRING_RESULTS}); request a smaller range"
        ));
    }
    let offset = base_offset
        .checked_add(
            u64::try_from(start).map_err(|_| "String result offset cannot be represented")?,
        )
        .ok_or("String result offset overflow")?;
    matches.push(StringMatch {
        offset,
        length: text.len(),
        text: text.to_string(),
    });
    Ok(())
}

pub(super) fn find_strings_in_bytes(
    bytes: &[u8],
    min_length: usize,
    base_offset: u64,
) -> Result<Vec<StringMatch>, String> {
    if bytes.len() > MAX_STRING_SCAN_BYTES {
        return Err(format!(
            "String scan byte budget exceeded (maximum {MAX_STRING_SCAN_BYTES})"
        ));
    }
    base_offset
        .checked_add(
            u64::try_from(bytes.len()).map_err(|_| "String scan length cannot be represented")?,
        )
        .ok_or("String scan range overflow")?;
    let mut matches = Vec::new();
    let mut current_start = None;
    let mut current_run = Vec::new();
    let mut pos = 0;

    while pos < bytes.len() {
        let byte = bytes[pos];
        let run_length =
            if byte == 0x09 || byte == 0x0A || byte == 0x0D || (0x20..=0x7E).contains(&byte) {
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
                        if text
                            .chars()
                            .all(|c| c == '\t' || c == '\n' || c == '\r' || !c.is_control())
                        {
                            push_string_match(&mut matches, base_offset, start, text)?;
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
                            if text
                                .chars()
                                .all(|c| c == '\t' || c == '\n' || c == '\r' || !c.is_control())
                            {
                                push_string_match(&mut matches, base_offset, start, text)?;
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
                if text
                    .chars()
                    .all(|c| c == '\t' || c == '\n' || c == '\r' || !c.is_control())
                {
                    push_string_match(&mut matches, base_offset, start, text)?;
                }
            }
        }
    }

    Ok(matches)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_hex_rejects_byte_budget_before_read() {
        let tmp = tempfile(b"A");
        assert!(read_hex_range(
            tmp.path().to_string_lossy().into_owned(),
            0,
            1024 * 1024 + 1
        )
        .is_err());
    }

    #[test]
    fn range_hex_rejects_offset_overflow_even_at_eof() {
        let tmp = tempfile(b"A");
        assert!(read_hex_range(tmp.path().to_string_lossy().into_owned(), u64::MAX, 1).is_err());
    }

    #[test]
    fn range_strings_rejects_byte_budget_before_read() {
        let tmp = tempfile(b"A");
        assert!(find_strings(
            tmp.path().to_string_lossy().into_owned(),
            0,
            16 * 1024 * 1024 + 1,
            1
        )
        .is_err());
    }

    #[test]
    fn range_strings_rejects_offset_overflow() {
        let tmp = tempfile(b"AA");
        assert!(find_strings(tmp.path().to_string_lossy().into_owned(), 1, usize::MAX, 1).is_err());
    }

    #[test]
    fn range_strings_rejects_result_budget_without_partial_success() {
        let tmp = tempfile(&b"A\0".repeat(10_001));
        assert!(find_strings(tmp.path().to_string_lossy().into_owned(), 0, 20_002, 1).is_err());
    }

    #[test]
    fn range_strings_respects_requested_length_and_offset() {
        let tmp = tempfile(b"\0HELLO\0WORLD\0");
        let result = find_strings(tmp.path().to_string_lossy().into_owned(), 1, 5, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, "HELLO");
        assert_eq!(result[0].offset, 1);
    }

    #[test]
    fn range_strings_accepts_exact_result_budget_and_bounds_all_flush_paths() {
        let data = b"A\0".repeat(10_000);
        assert_eq!(find_strings_in_bytes(&data, 1, 0).unwrap().len(), 10_000);
        let mut eof = data.clone();
        eof.push(b'A');
        assert!(find_strings_in_bytes(&eof, 1, 0)
            .unwrap_err()
            .contains("result budget"));
        let mut invalid_utf8 = eof;
        invalid_utf8.extend_from_slice(&[0xC2, b'A']);
        assert!(find_strings_in_bytes(&invalid_utf8, 1, 0)
            .unwrap_err()
            .contains("result budget"));
        assert!(find_strings_in_bytes(b"A", 1, u64::MAX).is_err());
    }

    #[test]
    fn range_readers_accept_exact_byte_budgets_without_reading_full_file() {
        let tmp = tempfile(b"HELLO");
        let path = tmp.path().to_string_lossy().into_owned();
        assert_eq!(
            read_hex_range(path.clone(), 0, MAX_HEX_BYTES).unwrap(),
            b"HELLO"
        );
        assert_eq!(
            find_strings(path, 0, MAX_STRING_SCAN_BYTES, 1).unwrap()[0].text,
            "HELLO"
        );
    }

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
        let matches = find_strings_in_bytes(data, 4, 0).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].text, "Hello World");
    }

    #[test]
    fn find_strings_in_bytes_respects_min_length() {
        let data = b"\x00ABC\x00ABCDEFGH\x00";
        let matches = find_strings_in_bytes(data, 5, 0).unwrap();
        // "ABC" is only 3 chars — should NOT appear
        assert!(!matches.iter().any(|m| m.text == "ABC"));
        // "ABCDEFGH" is 8 chars — should appear
        assert!(matches.iter().any(|m| m.text == "ABCDEFGH"));
    }

    #[test]
    fn find_strings_in_bytes_offset_is_correct() {
        let data = b"\x00\x00\x00Hello\x00";
        let matches = find_strings_in_bytes(data, 4, 100).unwrap();
        assert_eq!(matches[0].offset, 103); // base 100 + position 3
    }

    #[test]
    fn find_strings_in_bytes_empty_input_returns_empty() {
        let matches = find_strings_in_bytes(b"", 4, 0).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn find_strings_in_bytes_no_strings_returns_empty() {
        let data = vec![0x00u8, 0x01, 0x02, 0x80, 0xFF];
        let matches = find_strings_in_bytes(&data, 4, 0).unwrap();
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
            let mut path = std::env::var_os("TMPDIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            path.push(format!(
                "hexhawk_test_{}.bin",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos()
            ));
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
