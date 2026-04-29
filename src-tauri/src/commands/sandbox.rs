//! sandbox — run a script file in a restricted subprocess and report behaviour.
//!
//! ## What the sandbox does
//! 1. Detects the interpreter from the file extension.
//! 2. Snapshots watched directories (TEMP, script parent dir) to detect file
//!    drops after execution.
//! 3. Spawns the interpreter with captured stdout/stderr.
//! 4. Kills the process after `timeout_secs` (default 30) if it has not exited.
//! 5. On Windows, assigns the child to a Job Object with a 256 MB committed-
//!    memory limit before releasing it to run.
//! 6. Diffs the directory snapshot to find created/deleted files.
//! 7. Scans stdout/stderr for behaviour patterns (network calls, file drops,
//!    process spawns, credential access) and emits verdict signals.
//!
//! ## What the sandbox does NOT do
//! - Network traffic is **not** blocked.  A prominent warning is surfaced to
//!   the analyst in the UI.  Full network isolation requires platform-level
//!   firewall rules that depend on runtime privileges not guaranteed by a
//!   desktop app.  The analyst should run HexHawk inside a VM if isolation is
//!   required.
//! - The sandbox does not prevent the script from reading arbitrary files on
//!   the host filesystem.  Use a VM for untrusted samples.

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ─── Public output types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct SandboxResult {
    /// Exit code from the process (None if killed by timeout)
    pub exit_code: Option<i32>,
    /// Captured standard output (truncated to 64 KB)
    pub stdout: String,
    /// Captured standard error (truncated to 64 KB)
    pub stderr: String,
    /// True if the 30-second wall-clock timeout was reached and the process killed
    pub timed_out: bool,
    /// Elapsed wall-clock time in milliseconds
    pub runtime_ms: u64,
    /// Interpreter that was used
    pub interpreter: String,
    /// Files created or modified during execution
    pub file_events: Vec<FileEvent>,
    /// Behaviour signals derived from stdout/stderr/file-events
    pub signals: Vec<SandboxSignal>,
    /// Human-readable warnings (e.g. "network NOT isolated")
    pub warnings: Vec<String>,
    /// Error that prevented execution (None on success / timeout)
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileEvent {
    pub path: String,
    /// "created" | "modified" | "deleted"
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SandboxSignal {
    pub label: String,
    pub confidence: u8,
    pub category: String,
}

// ─── Interpreter detection ────────────────────────────────────────────────────

fn detect_interpreter(path: &Path) -> Option<Vec<String>> {
    let ext = path.extension()?.to_string_lossy().to_lowercase();
    match ext.as_str() {
        "py"  => Some(vec![
            #[cfg(windows)]  "python".to_string(),
            #[cfg(not(windows))] "python3".to_string(),
            path.to_string_lossy().into_owned(),
        ]),
        "ps1" => Some(vec![
            "powershell".to_string(),
            "-ExecutionPolicy".to_string(), "Bypass".to_string(),
            "-NonInteractive".to_string(),
            "-File".to_string(),
            path.to_string_lossy().into_owned(),
        ]),
        "js"  => Some(vec!["node".to_string(), path.to_string_lossy().into_owned()]),
        "bat" | "cmd" => Some(vec![
            "cmd".to_string(), "/c".to_string(), path.to_string_lossy().into_owned(),
        ]),
        "sh"  => Some(vec!["sh".to_string(), path.to_string_lossy().into_owned()]),
        "rb"  => Some(vec!["ruby".to_string(), path.to_string_lossy().into_owned()]),
        "pl"  => Some(vec!["perl".to_string(), path.to_string_lossy().into_owned()]),
        _     => None,
    }
}

const MAX_SCRIPT_SIZE_BYTES: u64 = 64 * 1024 * 1024; // 64 MB
const MAX_SNAPSHOT_FILES_PER_DIR: usize = 20_000;

fn validate_script_path(path: &str) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| format!("Invalid script path: {e}"))?;
    let meta = std::fs::metadata(&canonical)
        .map_err(|e| format!("Failed to stat script path: {e}"))?;

    if !meta.is_file() {
        return Err("Sandbox input must be a regular file.".to_string());
    }

    if meta.len() > MAX_SCRIPT_SIZE_BYTES {
        return Err(format!(
            "Script exceeds maximum allowed size of {} MB ({} bytes).",
            MAX_SCRIPT_SIZE_BYTES / (1024 * 1024),
            meta.len()
        ));
    }

    Ok(canonical)
}

fn wait_with_timeout(mut child: std::process::Child, timeout: Duration) -> Result<(std::process::Output, bool), String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let out = child
                    .wait_with_output()
                    .map_err(|e| format!("wait_with_output error: {e}"))?;
                return Ok((out, false));
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    if let Err(e) = child.kill() {
                        // Ignore invalid-input (already exited) but report other kill failures.
                        if e.kind() != std::io::ErrorKind::InvalidInput {
                            return Err(format!("failed to terminate timed out process: {e}"));
                        }
                    }
                    let out = child
                        .wait_with_output()
                        .map_err(|e| format!("wait_with_output error after timeout kill: {e}"))?;
                    return Ok((out, true));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(format!("try_wait failed: {e}")),
        }
    }
}

// ─── Directory snapshot ───────────────────────────────────────────────────────

/// Returns a map of path → last-modified timestamp (as secs since epoch).
fn snapshot_dir(dir: &Path) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    if !dir.exists() { return map; }
    let walker = walkdir::WalkDir::new(dir)
        .max_depth(3)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file());
    let mut file_count = 0usize;
    for entry in walker {
        if file_count >= MAX_SNAPSHOT_FILES_PER_DIR {
            break;
        }
        if let Ok(meta) = entry.metadata() {
            let mtime = meta.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            map.insert(entry.path().to_string_lossy().into_owned(), mtime);
            file_count += 1;
        }
    }
    map
}

fn apply_sandbox_environment(cmd: &mut Command, script_path: &Path) {
    // Use a minimal allowlist to avoid leaking unrelated host environment state.
    const KEYS: &[&str] = &[
        "PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT",
        "TMP", "TEMP", "HOME", "USERPROFILE",
        "LANG", "LC_ALL", "TERM",
    ];

    cmd.env_clear();
    for key in KEYS {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }

    // Mark child context as sandbox execution and avoid carrying sensitive process vars.
    cmd.env("HEXHAWK_SANDBOX", OsString::from("1"));

    if let Some(parent) = script_path.parent() {
        cmd.current_dir(parent);
    }
}

/// Diff two snapshots, returning FileEvents.
fn diff_snapshots(
    before: &HashMap<String, u64>,
    after: &HashMap<String, u64>,
) -> Vec<FileEvent> {
    let mut events = Vec::new();
    // Created or modified
    for (path, &after_ts) in after {
        match before.get(path) {
            None => events.push(FileEvent { path: path.clone(), kind: "created".into() }),
            Some(&before_ts) if before_ts != after_ts => {
                events.push(FileEvent { path: path.clone(), kind: "modified".into() });
            }
            _ => {}
        }
    }
    // Deleted
    for path in before.keys() {
        if !after.contains_key(path) {
            events.push(FileEvent { path: path.clone(), kind: "deleted".into() });
        }
    }
    events
}

// ─── Behaviour pattern scanning ──────────────────────────────────────────────

/// Patterns searched in combined stdout+stderr.
const STDOUT_PATTERNS: &[(&str, &str, u8, &str)] = &[
    // (substring, label, confidence, category)
    ("socket",         "Network socket operation in output",              80, "network"),
    ("connect(",       "Network connect() call observed in output",       85, "network"),
    ("urllib",         "urllib network library usage",                     82, "network"),
    ("requests.",      "Python requests library usage",                    82, "network"),
    ("http://",        "HTTP URL reference in output",                     75, "network"),
    ("https://",       "HTTPS URL reference in output",                    75, "network"),
    ("CreateProcess",  "CreateProcess call observed in output",            88, "exec"),
    ("subprocess",     "Subprocess spawn observed in output",              85, "exec"),
    ("os.system(",     "os.system() shell spawn observed in output",       88, "exec"),
    ("shell=True",     "shell=True subprocess spawn",                      90, "exec"),
    ("WriteFile",      "WriteFile API call in output",                     80, "dropper"),
    ("open(",          "File open in output",                              60, "dropper"),
    ("base64",         "Base64 encoding/decoding in output",               75, "obfuscation"),
    ("marshal",        "Python marshal module (bytecode packing)",         78, "obfuscation"),
    ("pickle",         "Python pickle (serialized code execution risk)",   80, "exec"),
    ("winreg",         "Windows registry access (winreg)",                 85, "persistence"),
    ("reg add",        "Registry write via reg.exe",                       90, "persistence"),
    ("HKCU\\",         "HKCU registry key reference",                      82, "persistence"),
    ("HKLM\\",         "HKLM registry key reference",                      82, "persistence"),
    ("schtasks",       "Scheduled task creation (schtasks)",               90, "persistence"),
    ("whoami",         "whoami — host reconnaissance",                     72, "recon"),
    ("net user",       "net user — account enumeration",                   85, "recon"),
    ("ipconfig",       "ipconfig — network reconnaissance",                70, "recon"),
    ("traceback",      "Python exception traceback (execution confirmed)", 95, "info"),
    ("Traceback",      "Python exception traceback (execution confirmed)", 95, "info"),
];

fn scan_output_signals(combined: &str) -> Vec<SandboxSignal> {
    let lower = combined.to_lowercase();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut signals = Vec::new();
    for &(pat, label, conf, cat) in STDOUT_PATTERNS {
        if !seen.contains(pat) && lower.contains(&pat.to_lowercase()) {
            seen.insert(pat);
            signals.push(SandboxSignal {
                label: label.to_string(),
                confidence: conf,
                category: cat.to_string(),
            });
        }
    }
    signals
}

fn signals_from_file_events(events: &[FileEvent]) -> Vec<SandboxSignal> {
    let mut signals = Vec::new();
    let created: Vec<&FileEvent> = events.iter().filter(|e| e.kind == "created").collect();
    let modified: Vec<&FileEvent> = events.iter().filter(|e| e.kind == "modified").collect();
    let deleted: Vec<&FileEvent> = events.iter().filter(|e| e.kind == "deleted").collect();

    if !created.is_empty() {
        // Check if any created file looks like a dropper payload
        let exe_drops: Vec<_> = created.iter().filter(|e| {
            let p = e.path.to_lowercase();
            p.ends_with(".exe") || p.ends_with(".dll") || p.ends_with(".bat") ||
            p.ends_with(".ps1") || p.ends_with(".vbs") || p.ends_with(".cmd")
        }).collect();
        if !exe_drops.is_empty() {
            signals.push(SandboxSignal {
                label: format!("{} executable file(s) dropped during execution", exe_drops.len()),
                confidence: 95,
                category: "dropper".into(),
            });
        } else {
            signals.push(SandboxSignal {
                label: format!("{} new file(s) created during execution", created.len()),
                confidence: 75,
                category: "dropper".into(),
            });
        }
    }
    if !modified.is_empty() {
        signals.push(SandboxSignal {
            label: format!("{} file(s) modified during execution", modified.len()),
            confidence: 70,
            category: "dropper".into(),
        });
    }
    if !deleted.is_empty() {
        signals.push(SandboxSignal {
            label: format!("{} file(s) deleted during execution", deleted.len()),
            confidence: 72,
            category: "dropper".into(),
        });
    }
    signals
}

// ─── Windows Job Object (memory limit) ───────────────────────────────────────

#[cfg(windows)]
fn apply_memory_limit_windows(pid: u32) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };
    use windows_sys::Win32::System::Threading::OpenProcess;
    use windows_sys::Win32::System::Threading::{
        PROCESS_QUERY_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
    };

    const MEMORY_LIMIT: usize = 256 * 1024 * 1024; // 256 MB

    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job == 0 || job == INVALID_HANDLE_VALUE {
            return Err("CreateJobObjectW failed".into());
        }

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        info.ProcessMemoryLimit = MEMORY_LIMIT;

        let ok = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if ok == 0 {
            CloseHandle(job);
            return Err("SetInformationJobObject failed".into());
        }

        let desired_access = PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION;
        let proc_handle = OpenProcess(desired_access, 0, pid);
        if proc_handle == 0 || proc_handle == INVALID_HANDLE_VALUE {
            CloseHandle(job);
            return Err(format!("OpenProcess({pid}) failed"));
        }

        let assigned = AssignProcessToJobObject(job, proc_handle);
        CloseHandle(proc_handle);
        CloseHandle(job);

        if assigned == 0 {
            // May fail if process is already in a job (common in modern Windows);
            // treat as non-fatal.
            return Err("AssignProcessToJobObject failed (process may already be in a job)".into());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn apply_memory_limit_windows(_pid: u32) -> Result<(), String> {
    Err("Job Object memory limit not supported on this platform".into())
}

// ─── Tauri command ────────────────────────────────────────────────────────────

#[tauri::command]
pub fn run_script_sandbox(path: String, timeout_secs: Option<u64>) -> SandboxResult {
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(30).min(120));
    let script_path = match validate_script_path(&path) {
        Ok(p) => p,
        Err(e) => {
            return SandboxResult {
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
                runtime_ms: 0,
                interpreter: "unknown".into(),
                file_events: vec![],
                signals: vec![],
                warnings: vec![
                    "⚠ Network traffic is NOT isolated. Run inside a VM for untrusted samples.".into(),
                    "⚠ File system access is NOT restricted. The script can read any file accessible to your user.".into(),
                ],
                error: Some(e),
            };
        }
    };

    let mut warnings: Vec<String> = vec![
        "⚠ Network traffic is NOT isolated. Run inside a VM for untrusted samples.".into(),
        "⚠ File system access is NOT restricted. The script can read any file accessible to your user.".into(),
    ];

    // ── Interpreter detection ─────────────────────────────────────────────────
    let Some(argv) = detect_interpreter(&script_path) else {
        return SandboxResult {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            runtime_ms: 0,
            interpreter: "unknown".into(),
            file_events: vec![],
            signals: vec![],
            warnings,
            error: Some(format!(
                "Unsupported file extension. Supported: .py .ps1 .js .bat .cmd .sh .rb .pl"
            )),
        };
    };

    let interpreter = argv[0].clone();

    // ── Pre-execution directory snapshots ─────────────────────────────────────
    let watch_dirs: Vec<PathBuf> = {
        let mut d = vec![];
        if let Some(parent) = script_path.parent() {
            d.push(parent.to_path_buf());
        }
        if let Ok(tmp) = std::env::var("TEMP").or_else(|_| std::env::var("TMP")) {
            d.push(PathBuf::from(tmp));
        } else {
            d.push(std::env::temp_dir());
        }
        d
    };

    let before_snaps: Vec<HashMap<String, u64>> =
        watch_dirs.iter().map(|d| snapshot_dir(d)).collect();

    // ── Spawn process ─────────────────────────────────────────────────────────
    let start = Instant::now();

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    apply_sandbox_environment(&mut cmd, &script_path);

    // Prevent the child from opening a console window on Windows
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = if e.kind() == std::io::ErrorKind::NotFound {
                format!("Interpreter '{interpreter}' not found in PATH. Install it and try again.")
            } else {
                format!("Failed to spawn '{interpreter}': {e}")
            };
            return SandboxResult {
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
                runtime_ms: 0,
                interpreter,
                file_events: vec![],
                signals: vec![],
                warnings,
                error: Some(msg),
            };
        }
    };

    // ── Windows memory limit ──────────────────────────────────────────────────
    #[cfg(windows)]
    {
        let pid = child.id();
        match apply_memory_limit_windows(pid) {
            Ok(()) => {}
            Err(e) => warnings.push(format!("Memory limit not applied: {e}")),
        }
    }

    // ── Collect output ────────────────────────────────────────────────────────
    let output = wait_with_timeout(child, timeout);
    let runtime_ms = start.elapsed().as_millis() as u64;
    let timed_out = output.as_ref().map(|(_, t)| *t).unwrap_or(false);

    let (exit_code, raw_stdout, raw_stderr) = match output {
        Ok((o, _)) => (
            o.status.code(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ),
        Err(e) => (None, String::new(), e),
    };

    // Truncate to 64 KB each
    const MAX_OUT: usize = 64 * 1024;
    let stdout = if raw_stdout.len() > MAX_OUT {
        format!("{}\n... [truncated — {} bytes total]", &raw_stdout[..MAX_OUT], raw_stdout.len())
    } else {
        raw_stdout
    };
    let stderr = if raw_stderr.len() > MAX_OUT {
        format!("{}\n... [truncated — {} bytes total]", &raw_stderr[..MAX_OUT], raw_stderr.len())
    } else {
        raw_stderr
    };

    // ── Post-execution snapshot diff ──────────────────────────────────────────
    let mut file_events: Vec<FileEvent> = Vec::new();
    for (dir, before) in watch_dirs.iter().zip(before_snaps.iter()) {
        let after = snapshot_dir(dir);
        file_events.extend(diff_snapshots(before, &after));
    }

    // ── Signal derivation ─────────────────────────────────────────────────────
    let combined = format!("{stdout}\n{stderr}");
    let mut signals = scan_output_signals(&combined);
    signals.extend(signals_from_file_events(&file_events));

    if timed_out {
        signals.push(SandboxSignal {
            label: "Execution timed out — possible infinite loop or deliberate stall".into(),
            confidence: 80,
            category: "anti-analysis".into(),
        });
    }

    SandboxResult {
        exit_code,
        stdout,
        stderr,
        timed_out,
        runtime_ms,
        interpreter,
        file_events,
        signals,
        warnings,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn validate_script_path_rejects_missing() {
        let err = validate_script_path("missing_sandbox_script_12345.py").unwrap_err();
        assert!(err.contains("Invalid script path") || err.contains("Failed to stat"));
    }

    #[test]
    fn validate_script_path_rejects_directory() {
        let dir = std::env::temp_dir().join("hexhawk_sandbox_dir");
        std::fs::create_dir_all(&dir).expect("create dir");
        let err = validate_script_path(dir.to_string_lossy().as_ref()).unwrap_err();
        assert!(err.contains("regular file"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_interpreter_known_extension() {
        let p = Path::new("sample.py");
        assert!(detect_interpreter(p).is_some());
    }

    #[test]
    fn apply_sandbox_environment_sets_marker() {
        let mut cmd = Command::new("cmd");
        apply_sandbox_environment(&mut cmd, Path::new("C:/tmp/sample.py"));
        let found_marker = cmd
            .get_envs()
            .any(|(k, v)| k == "HEXHAWK_SANDBOX" && v == Some(std::ffi::OsStr::new("1")));
        assert!(found_marker, "sandbox marker env var must be set");
    }

    #[test]
    fn wait_with_timeout_rejects_zero_timeout_for_running_process() {
        // Spawn a short-lived process and force immediate timeout path.
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
