// src-tauri/src/commands/corpus.rs
//
// Corpus logging command — appends one analysis result as a JSONL line to
//   {app_data_dir}/corpus/log.jsonl
//
// The `entry` parameter is an opaque JSON Value so the schema can evolve on
// the TypeScript side without requiring a Rust recompile.  The command is
// intentionally thin: validate nothing, just write and return.

use serde_json::Value;
use std::io::Write as _;
use std::path::Path;
use tauri::Manager as _;

const MAX_CORPUS_ENTRY_BYTES: usize = 256 * 1024;
const MAX_CORPUS_LOG_BYTES: u64 = 16 * 1024 * 1024;

fn serialize_entry(entry: &Value) -> Result<String, String> {
    let line =
        serde_json::to_string(entry).map_err(|e| format!("Failed to serialise entry: {e}"))?;
    if line.len() > MAX_CORPUS_ENTRY_BYTES {
        return Err(format!(
            "Corpus entry exceeds maximum size of {} bytes",
            MAX_CORPUS_ENTRY_BYTES
        ));
    }
    Ok(line)
}

fn should_rotate_log(current_bytes: u64, incoming_bytes: usize) -> bool {
    current_bytes.saturating_add(incoming_bytes as u64) > MAX_CORPUS_LOG_BYTES
}

fn rotate_log_if_needed(log_path: &Path, incoming_bytes: usize) -> Result<(), String> {
    let current_bytes = match std::fs::metadata(log_path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => return Err("Corpus log path is not a regular file".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(format!("Failed to inspect corpus log: {error}")),
    };
    if !should_rotate_log(current_bytes, incoming_bytes) {
        return Ok(());
    }

    let rotated_path = log_path.with_extension("jsonl.1");
    if rotated_path.exists() {
        std::fs::remove_file(&rotated_path)
            .map_err(|e| format!("Failed to replace rotated corpus log: {e}"))?;
    }
    std::fs::rename(log_path, rotated_path).map_err(|e| format!("Failed to rotate corpus log: {e}"))
}

/// Append one analysis log entry to the corpus JSONL file.
///
/// Creates `{app_data_dir}/corpus/` if it does not already exist.
/// Errors are returned as strings so the TypeScript caller can log them
/// without crashing the UI.
#[tauri::command]
pub fn log_analysis_result(app: tauri::AppHandle, entry: Value) -> Result<(), String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Could not resolve app data dir: {e}"))?;

    let corpus_dir = data_dir.join("corpus");
    std::fs::create_dir_all(&corpus_dir)
        .map_err(|e| format!("Failed to create corpus directory: {e}"))?;

    let log_path = corpus_dir.join("log.jsonl");

    let line = serialize_entry(&entry)?;
    let incoming_bytes = line.len().saturating_add(1);
    rotate_log_if_needed(&log_path, incoming_bytes)?;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("Failed to open log file: {e}"))?;

    writeln!(file, "{line}").map_err(|e| format!("Failed to write log entry: {e}"))?;

    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn oversized_corpus_entry_is_rejected_before_write() {
        let entry = json!({ "payload": "x".repeat(MAX_CORPUS_ENTRY_BYTES) });
        let err = serialize_entry(&entry).expect_err("oversized entry must be rejected");
        assert!(err.contains("maximum"));
    }

    #[test]
    fn corpus_log_rotates_before_exceeding_its_bound() {
        assert!(should_rotate_log(MAX_CORPUS_LOG_BYTES - 2, 3));
        assert!(!should_rotate_log(MAX_CORPUS_LOG_BYTES - 2, 2));
    }

    #[test]
    fn entry_serialises_to_single_line() {
        let entry = json!({
            "hash":      "abc123",
            "filename":  "notepad.exe",
            "timestamp": "2026-04-19T12:00:00.000Z",
            "verdict":   "CLEAN",
            "confidence": 87,
        });
        let line = serde_json::to_string(&entry).unwrap();
        // A JSONL line must not contain a raw newline
        assert!(!line.contains('\n'));
    }
}
