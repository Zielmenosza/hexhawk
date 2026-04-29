//! constraint — Z3 SMT-LIB2 solver bridge (Milestone 6)
//!
//! Exposes one Tauri command:
//!
//! ```
//! solve_z3_constraint(smtlib: String) -> Z3Result
//! ```
//!
//! The command calls `z3 -in` (stdin mode) as a subprocess, writes the
//! supplied SMT-LIB2 string, and captures the result.
//!
//! Z3 is **not** bundled with HexHawk.  If it is not found in PATH the
//! command returns an error with installation instructions.

use serde::Serialize;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_SMTLIB_BYTES: usize = 1024 * 1024; // 1 MB

// ─── Result types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Z3Result {
    /// "sat" | "unsat" | "unknown" | "error"
    pub verdict: String,
    /// Full raw output from z3 (stdout)
    pub raw_output: String,
    /// Parsed candidate model values (key → value strings)
    pub model: Vec<Z3ModelEntry>,
    /// True if z3 was not found in PATH
    pub z3_missing: bool,
    /// Wall-clock time in milliseconds
    pub runtime_ms: u64,
    /// Human-readable error (None on success)
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Z3ModelEntry {
    pub name: String,
    pub value: String,
}

// ─── Tauri command ────────────────────────────────────────────────────────────

#[tauri::command]
pub fn solve_z3_constraint(smtlib: String, timeout_secs: Option<u64>) -> Z3Result {
    let timeout = timeout_secs.unwrap_or(10).min(60);
    let start = Instant::now();

    if smtlib.as_bytes().len() > MAX_SMTLIB_BYTES {
        return Z3Result {
            verdict: "error".into(),
            raw_output: String::new(),
            model: vec![],
            z3_missing: false,
            runtime_ms: start.elapsed().as_millis() as u64,
            error: Some(format!(
                "SMT-LIB payload too large ({} bytes, max {} bytes).",
                smtlib.as_bytes().len(),
                MAX_SMTLIB_BYTES
            )),
        };
    }

    // Spawn z3 -in (read from stdin)
    let mut child = match Command::new("z3")
        .args(["-in", &format!("-T:{timeout}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let missing = e.kind() == std::io::ErrorKind::NotFound;
            return Z3Result {
                verdict: "error".into(),
                raw_output: String::new(),
                model: vec![],
                z3_missing: missing,
                runtime_ms: start.elapsed().as_millis() as u64,
                error: Some(if missing {
                    "Z3 not found in PATH. Install Z3 (https://github.com/Z3Prover/z3/releases) \
                     and ensure `z3` is on your PATH.".into()
                } else {
                    format!("Failed to spawn z3: {e}")
                }),
            };
        }
    };

    // Write SMT-LIB2 to stdin
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(smtlib.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return Z3Result {
                verdict: "error".into(),
                raw_output: String::new(),
                model: vec![],
                z3_missing: false,
                runtime_ms: start.elapsed().as_millis() as u64,
                error: Some(format!("Failed to write SMT-LIB to z3 stdin: {e}")),
            };
        }
        // stdin dropped here → EOF sent to z3
    }

    // Wait with timeout (z3 has its own -T: flag but we guard here too)
    let timeout_dur = Duration::from_secs(timeout + 2);
    let (output, timed_out) = match wait_with_timeout(child, timeout_dur) {
        Ok(o) => o,
        Err(e) => {
            return Z3Result {
                verdict: "error".into(),
                raw_output: String::new(),
                model: vec![],
                z3_missing: false,
                runtime_ms: start.elapsed().as_millis() as u64,
                error: Some(format!("z3 execution error: {e}")),
            };
        }
    };

    if timed_out {
        return Z3Result {
            verdict: "error".into(),
            raw_output: String::from_utf8_lossy(&output.stdout).into_owned(),
            model: vec![],
            z3_missing: false,
            runtime_ms: start.elapsed().as_millis() as u64,
            error: Some(format!("z3 timed out after {} seconds", timeout_dur.as_secs())),
        };
    }

    let runtime_ms = start.elapsed().as_millis() as u64;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    // Combine for display
    let combined = if stderr.trim().is_empty() {
        stdout.clone()
    } else {
        format!("{stdout}\n; stderr:\n{stderr}")
    };

    let verdict = if stdout.trim_start().starts_with("sat") {
        "sat"
    } else if stdout.trim_start().starts_with("unsat") {
        "unsat"
    } else if stdout.trim_start().starts_with("unknown") {
        "unknown"
    } else {
        "error"
    };

    let model = if verdict == "sat" {
        parse_model(&stdout)
    } else {
        vec![]
    };

    Z3Result {
        verdict: verdict.into(),
        raw_output: combined,
        model,
        z3_missing: false,
        runtime_ms,
        error: if verdict == "error" && !stderr.is_empty() {
            Some(stderr.trim().to_string())
        } else {
            None
        },
    }
}

// ─── Model parser ─────────────────────────────────────────────────────────────

/// Very small parser for Z3 model output of the form:
/// ```
/// sat
/// (model
///   (define-fun input () (_ BitVec 64) #x000000000000cafe)
/// )
/// ```
fn parse_model(output: &str) -> Vec<Z3ModelEntry> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if !line.starts_with("(define-fun") { continue; }
        // (define-fun NAME () TYPE VALUE)
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { continue; }
        let name = parts[1].to_string();
        // Last token before ')' is the value
        let raw_value = parts.last().unwrap_or(&"?").trim_end_matches(')');
        let value = decode_bv_literal(raw_value);
        entries.push(Z3ModelEntry { name, value });
    }
    entries
}

/// Convert #xHEX or #bBIN literal to a decimal+hex display string.
fn decode_bv_literal(s: &str) -> String {
    if let Some(hex) = s.strip_prefix("#x") {
        if let Ok(v) = u64::from_str_radix(hex, 16) {
            return format!("{v} (0x{v:x})");
        }
    }
    if let Some(bin) = s.strip_prefix("#b") {
        if let Ok(v) = u64::from_str_radix(bin, 2) {
            return format!("{v} (0x{v:x})");
        }
    }
    s.to_string()
}

// ─── Platform timeout helper ──────────────────────────────────────────────────

fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<(std::process::Output, bool), String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let out = child.wait_with_output().map_err(|e| e.to_string())?;
                return Ok((out, false));
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let out = child.wait_with_output().map_err(|e| e.to_string())?;
                    return Ok((out, true));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn decode_bv_literal_hex() {
        assert_eq!(decode_bv_literal("#x10"), "16 (0x10)");
    }

    #[test]
    fn decode_bv_literal_bin() {
        assert_eq!(decode_bv_literal("#b1010"), "10 (0xa)");
    }

    #[test]
    fn smtlib_limit_is_sane() {
        assert!(MAX_SMTLIB_BYTES >= 1024);
    }

    #[test]
    fn solve_z3_constraint_rejects_oversized_input_before_spawn() {
        let huge = "(assert true)".repeat((MAX_SMTLIB_BYTES / 8) + 4);
        let res = solve_z3_constraint(huge, Some(1));
        assert_eq!(res.verdict, "error");
        let err = res.error.unwrap_or_default();
        assert!(err.contains("payload too large"));
    }

    #[test]
    fn wait_with_timeout_marks_running_process_as_timed_out() {
        #[cfg(windows)]
        let child = Command::new("cmd")
            .args(["/c", "ping", "127.0.0.1", "-n", "2", ">", "nul"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");

        #[cfg(not(windows))]
        let child = Command::new("sh")
            .args(["-c", "sleep 1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");

        let result = wait_with_timeout(child, Duration::from_millis(0)).expect("wait_with_timeout");
        assert!(result.1, "process should be marked as timed out");
    }
}
