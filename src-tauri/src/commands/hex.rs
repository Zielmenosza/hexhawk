use std::fs;

#[derive(Debug, serde::Serialize)]
pub struct StringMatch {
    pub offset: u64,
    pub length: usize,
    pub text: String,
}

#[tauri::command]
pub fn read_hex_range(path: String, offset: usize, length: usize) -> Result<Vec<u8>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;

    if offset >= data.len() {
        return Ok(vec![]);
    }

    let end = std::cmp::min(offset + length, data.len());
    Ok(data[offset..end].to_vec())
}

#[tauri::command]
pub fn find_strings(path: String, offset: usize, length: usize, min_length: usize) -> Result<Vec<StringMatch>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;

    if offset >= data.len() {
        return Ok(vec![]);
    }

    let end = std::cmp::min(offset + length, data.len());
    let slice = &data[offset..end];
    Ok(find_strings_in_bytes(slice, min_length, offset as u64))
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
