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
use tauri::Manager as _;

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

    let line =
        serde_json::to_string(&entry).map_err(|e| format!("Failed to serialise entry: {e}"))?;

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
    use serde_json::json;

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
