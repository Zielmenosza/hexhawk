// Guided process value scanning with candidate-bound one-shot edits and visible,
// bounded Freeze workers. It remains separate from debugger sessions and never
// suspends, injects into, hides from, or terminates the target.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CANDIDATES: usize = 500_000;
const MAX_PREVIEW: usize = 200;
const READ_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_CONCURRENT_SCANS: usize = 2;
const MAX_SCAN_SESSIONS: usize = 8;
const MAX_CANCELLED_REQUESTS: usize = 256;
const MAX_EDIT_PREVIEWS: usize = 16;
const EDIT_PREVIEW_TTL: Duration = Duration::from_secs(60);
const EDIT_ROLLBACK_TTL: Duration = Duration::from_secs(5 * 60);
const FREEZE_PREVIEW_TTL: Duration = Duration::from_secs(60);
const DEFAULT_FREEZE_INTERVAL_MS: u64 = 50;
const MIN_FREEZE_INTERVAL_MS: u64 = 50;
const MAX_FREEZE_INTERVAL_MS: u64 = 1_000;
const MAX_CONSECUTIVE_FREEZE_FAILURES: u8 = 5;
const MAX_PENDING_FREEZES: usize = 8;
const MAX_ACTIVE_FREEZES: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueProcess {
    pub pid: u32,
    pub name: String,
}

#[tauri::command]
pub fn value_process_list() -> Result<Vec<ValueProcess>, String> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err("Windows could not enumerate running processes.".to_string());
        }

        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut processes = Vec::new();
        let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while has_entry {
            if entry.th32ProcessID != 0 {
                let name_len = entry
                    .szExeFile
                    .iter()
                    .position(|value| *value == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);
                if !name.is_empty() {
                    processes.push(ValueProcess {
                        pid: entry.th32ProcessID,
                        name,
                    });
                }
            }
            has_entry = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        unsafe { CloseHandle(snapshot) };

        processes.sort_by(|left, right| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
                .then(left.pid.cmp(&right.pid))
        });
        processes.dedup_by_key(|process| process.pid);
        Ok(processes)
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("Running-process selection is currently available on Windows only.".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueScanRequest {
    pub value: i32,
    pub max_scan_bytes: Option<u64>,
    pub authorized: bool,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueMatch {
    pub address: String,
    pub current_value: i32,
    pub previous_value: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueScanSnapshot {
    pub scan_id: u32,
    pub pid: u32,
    pub process_name: String,
    pub value_type: String,
    pub candidate_count: usize,
    pub scanned_bytes: u64,
    pub scanned_regions: u32,
    pub complete: bool,
    pub matches: Vec<ValueMatch>,
    pub warnings: Vec<String>,
    pub authority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueEditPreviewRequest {
    pub scan_id: u32,
    pub address: String,
    pub new_value: i32,
    pub authorized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueEditPreview {
    pub confirmation_token: String,
    pub scan_id: u32,
    pub pid: u32,
    pub process_name: String,
    pub address: String,
    pub original_value: i32,
    pub new_value: i32,
    pub original_bytes_le: [u8; 4],
    pub new_bytes_le: [u8; 4],
    pub expires_in_seconds: u64,
    pub authority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueEditResult {
    pub pid: u32,
    pub process_name: String,
    pub address: String,
    pub original_value: i32,
    pub current_value: i32,
    pub rollback_token: Option<String>,
    pub authority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueEditCommitRequest {
    pub confirmation_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueFreezePreviewRequest {
    pub scan_id: u32,
    pub address: String,
    pub frozen_value: i32,
    pub authorized: bool,
    #[serde(default)]
    pub interval_milliseconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueFreezePreview {
    pub confirmation_token: String,
    pub scan_id: u32,
    pub pid: u32,
    pub process_name: String,
    pub address: String,
    pub original_value: i32,
    pub frozen_value: i32,
    pub interval_milliseconds: u64,
    pub expires_in_seconds: u64,
    pub authority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueFreezeCommitRequest {
    pub confirmation_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueFreezeStopRequest {
    pub freeze_id: String,
    pub restore_original: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValueFreezeState {
    pub freeze_id: String,
    pub pid: u32,
    pub process_name: String,
    pub address: String,
    pub original_value: i32,
    pub frozen_value: i32,
    pub interval_milliseconds: u64,
    pub active: bool,
    pub verified_writes: u64,
    pub last_observed_value: Option<i32>,
    pub stop_reason: Option<String>,
    pub restored_original: bool,
    pub authority: String,
}

struct PendingValueEdit {
    scan_id: u32,
    pid: u32,
    process_name: String,
    process_creation_key: u64,
    address: u64,
    original_value: i32,
    new_value: i32,
    expires_at: Instant,
    written: bool,
}

struct PendingValueFreeze {
    scan_id: u32,
    pid: u32,
    process_name: String,
    process_creation_key: u64,
    address: u64,
    original_value: i32,
    frozen_value: i32,
    interval: Duration,
    expires_at: Instant,
}

fn freeze_interval(milliseconds: u64) -> Result<Duration, String> {
    if !(MIN_FREEZE_INTERVAL_MS..=MAX_FREEZE_INTERVAL_MS).contains(&milliseconds) {
        return Err(format!(
            "Freeze speed must be between {MIN_FREEZE_INTERVAL_MS} and {MAX_FREEZE_INTERVAL_MS} ms."
        ));
    }
    Ok(Duration::from_millis(milliseconds))
}

fn should_stop_freeze_after_failure(error: &str, consecutive_failures: u8) -> bool {
    !error.contains("did not retain the requested value")
        || consecutive_failures >= MAX_CONSECUTIVE_FREEZE_FAILURES
}

fn actionable_freeze_failure(error: &str) -> String {
    if error.contains("did not retain the requested value") {
        format!(
            "Freeze stopped after {MAX_CONSECUTIVE_FREEZE_FAILURES} consecutive verification failures. The process is rewriting this address immediately, so it is probably a temporary or display copy. Change the visible value again, run Next Scan, and use the newly retained candidate."
        )
    } else {
        error.to_string()
    }
}

struct ActiveValueFreeze {
    pending: PendingValueFreeze,
    stop_requested: AtomicBool,
    restore_original: AtomicBool,
    state: Mutex<ValueFreezeState>,
}

struct ValueScanSession {
    request_id: String,
    pid: u32,
    process_name: String,
    process_creation_key: u64,
    candidates: Vec<(u64, i32)>,
    scanned_bytes: u64,
    scanned_regions: u32,
    complete: bool,
    warnings: Vec<String>,
    #[cfg(target_os = "windows")]
    process: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(target_os = "windows")]
unsafe impl Send for ValueScanSession {}

#[cfg(target_os = "windows")]
impl Drop for ValueScanSession {
    fn drop(&mut self) {
        if self.process != 0 {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.process);
            }
        }
    }
}

static SCAN_COUNTER: Lazy<Mutex<u32>> = Lazy::new(|| Mutex::new(0));
static VALUE_SCAN_SESSIONS: Lazy<Mutex<HashMap<u32, ValueScanSession>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static CANCELLED_REQUESTS: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));
static PENDING_VALUE_EDITS: Lazy<Mutex<HashMap<String, PendingValueEdit>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static PENDING_VALUE_FREEZES: Lazy<Mutex<HashMap<String, PendingValueFreeze>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static ACTIVE_VALUE_FREEZES: Lazy<Mutex<HashMap<String, Arc<ActiveValueFreeze>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static ACTIVE_SCANS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_FREEZE_WORKERS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_FREEZE_TARGETS: Lazy<Mutex<HashSet<(u32, u64, u64)>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

struct ScanWorkerPermit;

#[derive(Debug)]
struct FreezeWorkerPermit {
    target: (u32, u64, u64),
}

impl FreezeWorkerPermit {
    fn acquire(freeze: &PendingValueFreeze) -> Result<Self, String> {
        ACTIVE_FREEZE_WORKERS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_ACTIVE_FREEZES).then_some(active + 1)
            })
            .map_err(|_| "Too many value freezes are active; stop one first.".to_string())?;
        let target = (freeze.pid, freeze.process_creation_key, freeze.address);
        if !ACTIVE_FREEZE_TARGETS.lock().unwrap().insert(target) {
            ACTIVE_FREEZE_WORKERS.fetch_sub(1, Ordering::AcqRel);
            return Err("This exact process candidate already has an active freeze.".to_string());
        }
        Ok(Self { target })
    }
}

impl Drop for FreezeWorkerPermit {
    fn drop(&mut self) {
        ACTIVE_FREEZE_TARGETS.lock().unwrap().remove(&self.target);
        ACTIVE_FREEZE_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ScanWorkerPermit {
    fn acquire() -> Result<Self, String> {
        ACTIVE_SCANS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_CONCURRENT_SCANS).then_some(active + 1)
            })
            .map_err(|_| {
                "Too many value scans are already running; wait for one to finish.".to_string()
            })?;
        Ok(Self)
    }
}

impl Drop for ScanWorkerPermit {
    fn drop(&mut self) {
        ACTIVE_SCANS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn next_scan_id() -> u32 {
    let mut counter = SCAN_COUNTER.lock().unwrap();
    *counter = counter.saturating_add(1);
    *counter
}

fn format_address(address: u64) -> String {
    format!("0x{address:016X}")
}

fn parse_address(address: &str) -> Result<u64, String> {
    if address.len() != 18 || !address.starts_with("0x") {
        return Err(
            "Candidate address must use canonical 0x plus 16 hexadecimal digits.".to_string(),
        );
    }
    let raw = &address[2..];
    if !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Candidate address is invalid.".to_string());
    }
    u64::from_str_radix(raw, 16).map_err(|_| "Candidate address is invalid.".to_string())
}

fn next_edit_token() -> String {
    use rand::{rngs::OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn prune_expired_edits(edits: &mut HashMap<String, PendingValueEdit>) {
    let now = Instant::now();
    edits.retain(|_, edit| edit.expires_at > now);
}

fn prune_expired_freezes(freezes: &mut HashMap<String, PendingValueFreeze>) {
    let now = Instant::now();
    freezes.retain(|_, freeze| freeze.expires_at > now);
}

#[cfg(target_os = "windows")]
fn read_i32(process: windows_sys::Win32::Foundation::HANDLE, address: u64) -> Result<i32, String> {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    let mut bytes = [0u8; 4];
    let mut bytes_read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            address as *const _,
            bytes.as_mut_ptr() as *mut _,
            bytes.len(),
            &mut bytes_read,
        )
    };
    if ok == FALSE || bytes_read != bytes.len() {
        return Err("Could not read the exact candidate value.".to_string());
    }
    Ok(i32::from_le_bytes(bytes))
}

#[cfg(target_os = "windows")]
fn write_i32_checked(
    edit: &PendingValueEdit,
    expected: i32,
    replacement: i32,
) -> Result<i32, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            FALSE,
            edit.pid,
        )
    };
    if process == 0 {
        return Err("Could not open the target for the explicitly confirmed edit.".to_string());
    }
    let result = (|| {
        if read_process_creation_key(process)? != edit.process_creation_key {
            return Err("Target process identity changed; the edit was not applied.".to_string());
        }
        let current = read_i32(process, edit.address)?;
        if current != expected {
            return Err(format!(
                "Candidate changed from {expected} to {current}; preview it again before editing."
            ));
        }
        let bytes = replacement.to_le_bytes();
        let mut bytes_written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                process,
                edit.address as *const _,
                bytes.as_ptr() as *const _,
                bytes.len(),
                &mut bytes_written,
            )
        };
        if ok == FALSE || bytes_written != bytes.len() {
            return Err("The exact 4-byte edit could not be written.".to_string());
        }
        let verified = read_i32(process, edit.address)?;
        if verified != replacement {
            return Err(
                "Write verification failed; the target did not retain the requested value."
                    .to_string(),
            );
        }
        Ok(verified)
    })();
    unsafe { CloseHandle(process) };
    result
}

#[cfg(target_os = "windows")]
fn freeze_write_checked(
    freeze: &PendingValueFreeze,
    expected: i32,
    replacement: i32,
) -> Result<i32, String> {
    write_i32_checked(
        &PendingValueEdit {
            scan_id: freeze.scan_id,
            pid: freeze.pid,
            process_name: freeze.process_name.clone(),
            process_creation_key: freeze.process_creation_key,
            address: freeze.address,
            original_value: expected,
            new_value: replacement,
            expires_at: Instant::now() + freeze.interval,
            written: false,
        },
        expected,
        replacement,
    )
}

#[cfg(target_os = "windows")]
fn enforce_freeze_once(freeze: &PendingValueFreeze) -> Result<i32, String> {
    let observed = read_freeze_value(freeze)?;
    freeze_write_checked(freeze, observed, freeze.frozen_value)
}

#[cfg(target_os = "windows")]
fn start_freeze_with_retries(freeze: &PendingValueFreeze) -> Result<i32, String> {
    let mut last_error = None;
    for attempt in 1..=MAX_CONSECUTIVE_FREEZE_FAILURES {
        match enforce_freeze_once(freeze) {
            Ok(value) => return Ok(value),
            Err(error) => {
                if should_stop_freeze_after_failure(&error, attempt) {
                    return Err(actionable_freeze_failure(&error));
                }
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    Err(actionable_freeze_failure(
        last_error.as_deref().unwrap_or("Freeze could not start."),
    ))
}

fn freeze_state(active: &ActiveValueFreeze) -> ValueFreezeState {
    active.state.lock().unwrap().clone()
}

fn stop_freezes_for_scan(scan_id: u32) {
    for freeze in ACTIVE_VALUE_FREEZES.lock().unwrap().values() {
        if freeze.pending.scan_id == scan_id {
            freeze.restore_original.store(false, Ordering::Release);
            freeze.stop_requested.store(true, Ordering::Release);
        }
    }
    PENDING_VALUE_FREEZES
        .lock()
        .unwrap()
        .retain(|_, freeze| freeze.scan_id != scan_id);
}

pub fn value_freeze_stop_all() {
    let freezes: Vec<Arc<ActiveValueFreeze>> = ACTIVE_VALUE_FREEZES
        .lock()
        .unwrap()
        .values()
        .cloned()
        .collect();
    for freeze in &freezes {
        freeze.restore_original.store(false, Ordering::Release);
        freeze.stop_requested.store(true, Ordering::Release);
    }
    for _ in 0..20 {
        if freezes.iter().all(|freeze| !freeze_state(freeze).active) {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    PENDING_VALUE_FREEZES.lock().unwrap().clear();
}

fn validate_request(pid: u32, request: &ValueScanRequest) -> Result<u64, String> {
    if pid == 0 {
        return Err("PID 0 is not a valid scan target.".to_string());
    }
    if !request.authorized {
        return Err("Confirm that you are authorized to inspect this process.".to_string());
    }
    if request.request_id.len() < 16
        || request.request_id.len() > 80
        || !request
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("Value scan request ID is invalid.".to_string());
    }
    let budget = request.max_scan_bytes.unwrap_or(MAX_SCAN_BYTES);
    if budget == 0 || budget > MAX_SCAN_BYTES {
        return Err(format!(
            "Scan budget must be between 1 and {MAX_SCAN_BYTES} bytes."
        ));
    }
    Ok(budget)
}

fn scan_i32_exact(bytes: &[u8], base: u64, value: i32, out: &mut Vec<(u64, i32)>) -> bool {
    if bytes.len() < 4 {
        return true;
    }
    for offset in 0..=bytes.len() - 4 {
        let found = i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        if found == value {
            if out.len() >= MAX_CANDIDATES {
                return false;
            }
            out.push((base + offset as u64, found));
        }
    }
    true
}

#[cfg(target_os = "windows")]
fn read_process_creation_key(
    process: windows_sys::Win32::Foundation::HANDLE,
) -> Result<u64, String> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;

    let mut creation: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err("Could not verify target process identity.".to_string());
    }
    Ok(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
}

fn snapshot(scan_id: u32, session: &ValueScanSession) -> ValueScanSnapshot {
    ValueScanSnapshot {
        scan_id,
        pid: session.pid,
        process_name: session.process_name.clone(),
        value_type: "i32".to_string(),
        candidate_count: session.candidates.len(),
        scanned_bytes: session.scanned_bytes,
        scanned_regions: session.scanned_regions,
        complete: session.complete,
        matches: session
            .candidates
            .iter()
            .take(MAX_PREVIEW)
            .map(|(address, value)| ValueMatch {
                address: format_address(*address),
                current_value: *value,
                previous_value: None,
            })
            .collect(),
        warnings: session.warnings.clone(),
        authority: "runtime_observation_not_gyre_verdict".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn start_windows_scan(
    pid: u32,
    value: i32,
    budget: u64,
    request_id: String,
) -> Result<ValueScanSession, String> {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE,
        PAGE_WRITECOPY,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ,
    };

    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) };
    if process == 0 {
        return Err("Could not open the process for read-only inspection. Access may be denied or the process may have exited.".to_string());
    }

    let creation_key = match read_process_creation_key(process) {
        Ok(key) => key,
        Err(error) => {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(process) };
            return Err(error);
        }
    };
    let mut image_name = vec![0u16; 32_768];
    let mut image_name_len = image_name.len() as u32;
    let process_name = if unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            image_name.as_mut_ptr(),
            &mut image_name_len,
        )
    } != 0
    {
        let full = String::from_utf16_lossy(&image_name[..image_name_len as usize]);
        std::path::Path::new(&full)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown process")
            .to_string()
    } else {
        "unknown process".to_string()
    };
    let mut session = ValueScanSession {
        request_id,
        pid,
        process_name,
        process_creation_key: creation_key,
        candidates: Vec::new(),
        scanned_bytes: 0,
        scanned_regions: 0,
        complete: true,
        warnings: Vec::new(),
        process,
    };
    let mut address = 0usize;
    let mut previous_tail: Vec<u8> = Vec::new();

    loop {
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let queried = unsafe {
            VirtualQueryEx(
                process,
                address as *const _,
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            break;
        }
        let base = info.BaseAddress as usize;
        let region_size = info.RegionSize;
        let next = base.saturating_add(region_size);
        if next <= address {
            break;
        }
        address = next;

        let base_protection = info.Protect & 0xff;
        let readable = info.State == MEM_COMMIT
            && info.Protect & PAGE_GUARD == 0
            && matches!(
                base_protection,
                PAGE_READONLY
                    | PAGE_READWRITE
                    | PAGE_WRITECOPY
                    | PAGE_EXECUTE_READ
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY
            );
        if !readable || region_size == 0 {
            continue;
        }
        session.scanned_regions = session.scanned_regions.saturating_add(1);
        let mut offset = 0usize;
        previous_tail.clear();
        while offset < region_size {
            if session.scanned_bytes >= budget {
                session.complete = false;
                session.warnings.push(
                    "Scan stopped at the configured byte budget; results are partial.".to_string(),
                );
                return Ok(session);
            }
            let remaining_budget = (budget - session.scanned_bytes) as usize;
            let wanted = READ_CHUNK_BYTES
                .min(region_size - offset)
                .min(remaining_budget);
            if wanted == 0 {
                break;
            }
            let mut buffer = vec![0u8; wanted];
            let mut bytes_read = 0usize;
            let ok = unsafe {
                ReadProcessMemory(
                    process,
                    (base + offset) as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    wanted,
                    &mut bytes_read,
                )
            };
            if ok == FALSE || bytes_read == 0 {
                session.warnings.push(format!(
                    "Skipped an unreadable range near {}.",
                    format_address((base + offset) as u64)
                ));
                session.complete = false;
                break;
            }
            buffer.truncate(bytes_read);
            let mut scan = previous_tail.clone();
            scan.extend_from_slice(&buffer);
            let scan_base = (base + offset).saturating_sub(previous_tail.len()) as u64;
            if !scan_i32_exact(&scan, scan_base, value, &mut session.candidates) {
                session.complete = false;
                session.warnings.push(
                    "Candidate limit reached; refine the search with a changed value.".to_string(),
                );
                return Ok(session);
            }
            previous_tail = buffer[buffer.len().saturating_sub(3)..].to_vec();
            session.scanned_bytes = session.scanned_bytes.saturating_add(bytes_read as u64);
            offset = offset.saturating_add(bytes_read);
            if bytes_read < wanted {
                session.complete = false;
                session
                    .warnings
                    .push("A memory range was only partially readable.".to_string());
                break;
            }
        }
    }
    Ok(session)
}

#[tauri::command]
pub async fn value_scan_start(
    pid: u32,
    request: ValueScanRequest,
) -> Result<ValueScanSnapshot, String> {
    let budget = validate_request(pid, &request)?;
    #[cfg(target_os = "windows")]
    {
        if VALUE_SCAN_SESSIONS.lock().unwrap().len() >= MAX_SCAN_SESSIONS {
            return Err("Too many retained value scans; clear an existing scan first.".to_string());
        }
        tokio::task::spawn_blocking(move || {
            let _permit = ScanWorkerPermit::acquire()?;
            let scan_id = next_scan_id();
            let request_id = request.request_id;
            let session = start_windows_scan(pid, request.value, budget, request_id.clone())?;
            let result = snapshot(scan_id, &session);
            if CANCELLED_REQUESTS.lock().unwrap().remove(&request_id) {
                return Err("Value scan was cancelled.".to_string());
            }
            let mut sessions = VALUE_SCAN_SESSIONS.lock().unwrap();
            if sessions.len() >= MAX_SCAN_SESSIONS {
                return Err(
                    "Too many retained value scans; clear an existing scan first.".to_string(),
                );
            }
            sessions.insert(scan_id, session);
            Ok(result)
        })
        .await
        .map_err(|_| "Value scan worker terminated unexpectedly.".to_string())?
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (pid, request, budget);
        Err("Guided process value scanning is currently supported on Windows only.".to_string())
    }
}

#[tauri::command]
pub async fn value_scan_refine(scan_id: u32, value: i32) -> Result<ValueScanSnapshot, String> {
    #[cfg(target_os = "windows")]
    {
        tokio::task::spawn_blocking(move || {
            use windows_sys::Win32::Foundation::FALSE;
            use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
            let mut session = VALUE_SCAN_SESSIONS
                .lock()
                .unwrap()
                .remove(&scan_id)
                .ok_or_else(|| "Value scan session not found.".to_string())?;
            let operation = (|| {
                if read_process_creation_key(session.process)? != session.process_creation_key {
                    return Err("Target process identity changed; start a new scan.".to_string());
                }
                let mut refined = Vec::new();
                for (address, previous) in &session.candidates {
                    let mut bytes = [0u8; 4];
                    let mut bytes_read = 0usize;
                    let ok = unsafe {
                        ReadProcessMemory(
                            session.process,
                            *address as *const _,
                            bytes.as_mut_ptr() as *mut _,
                            4,
                            &mut bytes_read,
                        )
                    };
                    if ok != FALSE && bytes_read == 4 && i32::from_le_bytes(bytes) == value {
                        refined.push((*address, *previous));
                    }
                }
                session.candidates = refined;
                let mut result = snapshot(scan_id, &session);
                result.matches = session
                    .candidates
                    .iter()
                    .take(MAX_PREVIEW)
                    .map(|(address, previous)| ValueMatch {
                        address: format_address(*address),
                        current_value: value,
                        previous_value: Some(*previous),
                    })
                    .collect();
                for candidate in &mut session.candidates {
                    candidate.1 = value;
                }
                Ok(result)
            })();
            let was_cancelled = CANCELLED_REQUESTS
                .lock()
                .unwrap()
                .remove(&session.request_id);
            if !was_cancelled {
                VALUE_SCAN_SESSIONS.lock().unwrap().insert(scan_id, session);
            }
            if was_cancelled {
                Err("Value scan was cancelled.".to_string())
            } else {
                operation
            }
        })
        .await
        .map_err(|_| "Value scan worker terminated unexpectedly.".to_string())?
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (scan_id, value);
        Err("Guided process value scanning is currently supported on Windows only.".to_string())
    }
}

#[tauri::command]
pub fn value_edit_preview(request: ValueEditPreviewRequest) -> Result<ValueEditPreview, String> {
    if !request.authorized {
        return Err("Confirm that you are authorized to edit this process value.".to_string());
    }
    let address = parse_address(&request.address)?;
    #[cfg(target_os = "windows")]
    {
        let sessions = VALUE_SCAN_SESSIONS.lock().unwrap();
        let session = sessions
            .get(&request.scan_id)
            .ok_or_else(|| "Value scan session not found.".to_string())?;
        let tracked = session
            .candidates
            .iter()
            .find(|(candidate, _)| *candidate == address)
            .ok_or_else(|| "The address is not a candidate in this scan.".to_string())?;
        if read_process_creation_key(session.process)? != session.process_creation_key {
            return Err("Target process identity changed; start a new scan.".to_string());
        }
        let original_value = read_i32(session.process, address)?;
        if original_value != tracked.1 {
            return Err(format!(
                "Candidate changed from {} to {original_value}; run Next scan before editing.",
                tracked.1
            ));
        }
        if original_value == request.new_value {
            return Err("The requested value is already present at this candidate.".to_string());
        }
        let token = next_edit_token();
        let preview = ValueEditPreview {
            confirmation_token: token.clone(),
            scan_id: request.scan_id,
            pid: session.pid,
            process_name: session.process_name.clone(),
            address: format_address(address),
            original_value,
            new_value: request.new_value,
            original_bytes_le: original_value.to_le_bytes(),
            new_bytes_le: request.new_value.to_le_bytes(),
            expires_in_seconds: EDIT_PREVIEW_TTL.as_secs(),
            authority: "explicit_runtime_edit_not_gyre_verdict".to_string(),
        };
        let pending = PendingValueEdit {
            scan_id: request.scan_id,
            pid: session.pid,
            process_name: session.process_name.clone(),
            process_creation_key: session.process_creation_key,
            address,
            original_value,
            new_value: request.new_value,
            expires_at: Instant::now() + EDIT_PREVIEW_TTL,
            written: false,
        };
        drop(sessions);
        let mut edits = PENDING_VALUE_EDITS.lock().unwrap();
        prune_expired_edits(&mut edits);
        if edits.len() >= MAX_EDIT_PREVIEWS {
            return Err("Too many pending edit previews; let one expire or commit it.".to_string());
        }
        edits.insert(token, pending);
        Ok(preview)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (request, address);
        Err("Guided process value editing is currently supported on Windows only.".to_string())
    }
}

#[tauri::command]
pub fn value_edit_commit(request: ValueEditCommitRequest) -> Result<ValueEditResult, String> {
    #[cfg(target_os = "windows")]
    {
        let mut edit = {
            let mut edits = PENDING_VALUE_EDITS.lock().unwrap();
            prune_expired_edits(&mut edits);
            edits
                .remove(&request.confirmation_token)
                .ok_or_else(|| "Edit preview expired or was already used.".to_string())?
        };
        if edit.written {
            return Err("This edit preview was already used.".to_string());
        }
        {
            let sessions = VALUE_SCAN_SESSIONS.lock().unwrap();
            let session = sessions.get(&edit.scan_id).ok_or_else(|| {
                "Originating scan was cleared; preview the edit again.".to_string()
            })?;
            if session.pid != edit.pid
                || session.process_creation_key != edit.process_creation_key
                || !session.candidates.iter().any(|(address, value)| {
                    *address == edit.address && *value == edit.original_value
                })
            {
                return Err("Originating candidate changed; preview the edit again.".to_string());
            }
        }
        let verified = write_i32_checked(&edit, edit.original_value, edit.new_value)?;
        edit.written = true;
        edit.expires_at = Instant::now() + EDIT_ROLLBACK_TTL;
        let rollback_token = next_edit_token();
        let result = ValueEditResult {
            pid: edit.pid,
            process_name: edit.process_name.clone(),
            address: format_address(edit.address),
            original_value: edit.original_value,
            current_value: verified,
            rollback_token: Some(rollback_token.clone()),
            authority: "explicit_runtime_edit_not_gyre_verdict".to_string(),
        };
        PENDING_VALUE_EDITS
            .lock()
            .unwrap()
            .insert(rollback_token, edit);
        Ok(result)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = request;
        Err("Guided process value editing is currently supported on Windows only.".to_string())
    }
}

#[tauri::command]
pub fn value_edit_rollback(rollback_token: String) -> Result<ValueEditResult, String> {
    #[cfg(target_os = "windows")]
    {
        let edit = {
            let mut edits = PENDING_VALUE_EDITS.lock().unwrap();
            prune_expired_edits(&mut edits);
            edits
                .remove(&rollback_token)
                .ok_or_else(|| "Rollback expired or was already used.".to_string())?
        };
        if !edit.written {
            return Err("This token does not represent an applied edit.".to_string());
        }
        let verified = write_i32_checked(&edit, edit.new_value, edit.original_value)?;
        Ok(ValueEditResult {
            pid: edit.pid,
            process_name: edit.process_name,
            address: format_address(edit.address),
            original_value: edit.new_value,
            current_value: verified,
            rollback_token: None,
            authority: "explicit_runtime_edit_rollback_not_gyre_verdict".to_string(),
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = rollback_token;
        Err("Guided process value editing is currently supported on Windows only.".to_string())
    }
}

#[tauri::command]
pub fn value_freeze_preview(
    request: ValueFreezePreviewRequest,
) -> Result<ValueFreezePreview, String> {
    if !request.authorized {
        return Err("Confirm that you are authorized to freeze this process value.".to_string());
    }
    let address = parse_address(&request.address)?;
    #[cfg(target_os = "windows")]
    {
        let sessions = VALUE_SCAN_SESSIONS.lock().unwrap();
        let session = sessions
            .get(&request.scan_id)
            .ok_or_else(|| "Value scan session not found.".to_string())?;
        let tracked = session
            .candidates
            .iter()
            .find(|(candidate, _)| *candidate == address)
            .ok_or_else(|| "The address is not a candidate in this scan.".to_string())?;
        if read_process_creation_key(session.process)? != session.process_creation_key {
            return Err("Target process identity changed; start a new scan.".to_string());
        }
        let original_value = read_i32(session.process, address)?;
        if original_value != tracked.1 {
            return Err(format!(
                "Candidate changed from {} to {original_value}; run Next scan before freezing.",
                tracked.1
            ));
        }
        let interval = freeze_interval(
            request
                .interval_milliseconds
                .unwrap_or(DEFAULT_FREEZE_INTERVAL_MS),
        )?;
        let token = next_edit_token();
        let preview = ValueFreezePreview {
            confirmation_token: token.clone(),
            scan_id: request.scan_id,
            pid: session.pid,
            process_name: session.process_name.clone(),
            address: format_address(address),
            original_value,
            frozen_value: request.frozen_value,
            interval_milliseconds: interval.as_millis() as u64,
            expires_in_seconds: FREEZE_PREVIEW_TTL.as_secs(),
            authority: "explicit_runtime_freeze_not_gyre_verdict".to_string(),
        };
        let pending = PendingValueFreeze {
            scan_id: request.scan_id,
            pid: session.pid,
            process_name: session.process_name.clone(),
            process_creation_key: session.process_creation_key,
            address,
            original_value,
            frozen_value: request.frozen_value,
            interval,
            expires_at: Instant::now() + FREEZE_PREVIEW_TTL,
        };
        drop(sessions);
        let mut freezes = PENDING_VALUE_FREEZES.lock().unwrap();
        prune_expired_freezes(&mut freezes);
        if freezes.len() >= MAX_PENDING_FREEZES {
            return Err(
                "Too many pending freeze previews; let one expire or start it.".to_string(),
            );
        }
        freezes.insert(token, pending);
        Ok(preview)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (request, address);
        Err("Guided value freezing is currently supported on Windows only.".to_string())
    }
}

#[tauri::command]
pub fn value_freeze_commit(request: ValueFreezeCommitRequest) -> Result<ValueFreezeState, String> {
    #[cfg(target_os = "windows")]
    {
        let pending = {
            let mut pending_freezes = PENDING_VALUE_FREEZES.lock().unwrap();
            prune_expired_freezes(&mut pending_freezes);
            pending_freezes
                .remove(&request.confirmation_token)
                .ok_or_else(|| "Freeze preview expired or was already used.".to_string())?
        };
        {
            let sessions = VALUE_SCAN_SESSIONS.lock().unwrap();
            let session = sessions.get(&pending.scan_id).ok_or_else(|| {
                "Originating scan was cleared; preview the freeze again.".to_string()
            })?;
            if session.pid != pending.pid
                || session.process_creation_key != pending.process_creation_key
                || !session.candidates.iter().any(|(address, value)| {
                    *address == pending.address && *value == pending.original_value
                })
            {
                return Err("Originating candidate changed; preview the freeze again.".to_string());
            }
        }
        let worker_permit = FreezeWorkerPermit::acquire(&pending)?;
        let verified = start_freeze_with_retries(&pending)?;
        let freeze_id = next_edit_token();
        let initial_state = ValueFreezeState {
            freeze_id: freeze_id.clone(),
            pid: pending.pid,
            process_name: pending.process_name.clone(),
            address: format_address(pending.address),
            original_value: pending.original_value,
            frozen_value: pending.frozen_value,
            interval_milliseconds: pending.interval.as_millis() as u64,
            active: true,
            verified_writes: 1,
            last_observed_value: Some(verified),
            stop_reason: None,
            restored_original: false,
            authority: "explicit_runtime_freeze_not_gyre_verdict".to_string(),
        };
        let active = Arc::new(ActiveValueFreeze {
            pending,
            stop_requested: AtomicBool::new(false),
            restore_original: AtomicBool::new(false),
            state: Mutex::new(initial_state.clone()),
        });
        {
            let mut active_freezes = ACTIVE_VALUE_FREEZES.lock().unwrap();
            active_freezes.retain(|_, freeze| freeze_state(freeze).active);
            active_freezes.insert(freeze_id, active.clone());
        }
        std::thread::spawn(move || {
            let _worker_permit = worker_permit;
            let mut consecutive_verification_failures = 0_u8;
            loop {
                std::thread::sleep(active.pending.interval);
                if active.stop_requested.load(Ordering::Acquire) {
                    let mut state = active.state.lock().unwrap();
                    state.active = false;
                    state.stop_reason = Some("Stopped by user or panel lifecycle.".to_string());
                    if active.restore_original.load(Ordering::Acquire) {
                        match freeze_write_checked(
                            &active.pending,
                            active.pending.frozen_value,
                            active.pending.original_value,
                        ) {
                            Ok(value) => {
                                state.last_observed_value = Some(value);
                                state.restored_original = true;
                            }
                            Err(error) => {
                                state.stop_reason = Some(format!(
                                    "Stopped; original value was not restored safely: {error}"
                                ))
                            }
                        }
                    }
                    break;
                }
                match enforce_freeze_once(&active.pending) {
                    Ok(current) => {
                        consecutive_verification_failures = 0;
                        let mut state = active.state.lock().unwrap();
                        state.last_observed_value = Some(current);
                        state.verified_writes = state.verified_writes.saturating_add(1);
                        state.stop_reason = None;
                    }
                    Err(error) => {
                        consecutive_verification_failures =
                            consecutive_verification_failures.saturating_add(1);
                        if should_stop_freeze_after_failure(
                            &error,
                            consecutive_verification_failures,
                        ) {
                            let mut state = active.state.lock().unwrap();
                            state.active = false;
                            state.stop_reason = Some(actionable_freeze_failure(&error));
                            break;
                        }
                        let observed = read_freeze_value(&active.pending).ok();
                        let mut state = active.state.lock().unwrap();
                        state.last_observed_value = observed;
                        state.stop_reason = Some(format!(
                            "The process rewrote this address; HexHawk is retrying ({consecutive_verification_failures}/{MAX_CONSECUTIVE_FREEZE_FAILURES})."
                        ));
                    }
                }
            }
        });
        Ok(initial_state)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = request;
        Err("Guided value freezing is currently supported on Windows only.".to_string())
    }
}

#[cfg(target_os = "windows")]
fn read_freeze_value(freeze: &PendingValueFreeze) -> Result<i32, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            freeze.pid,
        )
    };
    if process == 0 {
        return Err("Target process exited or became unavailable; freeze stopped.".to_string());
    }
    let result = (|| {
        if read_process_creation_key(process)? != freeze.process_creation_key {
            return Err("Target process identity changed; freeze stopped.".to_string());
        }
        read_i32(process, freeze.address)
    })();
    unsafe { CloseHandle(process) };
    result
}

#[tauri::command]
pub fn value_freeze_status(freeze_id: String) -> Result<ValueFreezeState, String> {
    ACTIVE_VALUE_FREEZES
        .lock()
        .unwrap()
        .get(&freeze_id)
        .map(|freeze| freeze_state(freeze))
        .ok_or_else(|| "Value freeze not found.".to_string())
}

#[tauri::command]
pub fn value_freeze_stop(request: ValueFreezeStopRequest) -> Result<ValueFreezeState, String> {
    let freeze = ACTIVE_VALUE_FREEZES
        .lock()
        .unwrap()
        .get(&request.freeze_id)
        .cloned()
        .ok_or_else(|| "Value freeze not found.".to_string())?;
    freeze
        .restore_original
        .store(request.restore_original, Ordering::Release);
    freeze.stop_requested.store(true, Ordering::Release);
    for _ in 0..20 {
        let state = freeze_state(&freeze);
        if !state.active {
            return Ok(state);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Ok(freeze_state(&freeze))
}

#[tauri::command]
pub fn value_scan_cancel(scan_id: u32) -> Result<(), String> {
    stop_freezes_for_scan(scan_id);
    if VALUE_SCAN_SESSIONS
        .lock()
        .unwrap()
        .remove(&scan_id)
        .is_none()
    {
        return Err("Value scan session not found.".to_string());
    }
    Ok(())
}

#[tauri::command]
pub fn value_scan_cancel_request(request_id: String) -> Result<(), String> {
    if request_id.len() < 16 || request_id.len() > 80 {
        return Err("Value scan request ID is invalid.".to_string());
    }
    {
        let mut cancelled = CANCELLED_REQUESTS.lock().unwrap();
        if !cancelled.contains(&request_id) && cancelled.len() >= MAX_CANCELLED_REQUESTS {
            return Err("Too many pending value scan cancellations.".to_string());
        }
        cancelled.insert(request_id.clone());
    }
    let scan_id = VALUE_SCAN_SESSIONS
        .lock()
        .unwrap()
        .iter()
        .find_map(|(scan_id, session)| (session.request_id == request_id).then_some(*scan_id));
    if let Some(scan_id) = scan_id {
        stop_freezes_for_scan(scan_id);
        VALUE_SCAN_SESSIONS.lock().unwrap().remove(&scan_id);
        CANCELLED_REQUESTS.lock().unwrap().remove(&request_id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    static FREEZE_TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
    // These two tests intentionally mutate the same process-global cancellation
    // registry; isolate only that fixture, not production admission or the runner.
    static CANCELLATION_TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[cfg(target_os = "windows")]
    #[test]
    fn running_process_picker_includes_current_process() {
        let current_pid = std::process::id();
        let processes = value_process_list().expect("Windows process enumeration should succeed");
        assert!(processes.iter().any(|process| process.pid == current_pid));
        assert!(processes.windows(2).all(|pair| {
            pair[0].name.to_ascii_lowercase() <= pair[1].name.to_ascii_lowercase()
                || pair[0].name.eq_ignore_ascii_case(&pair[1].name)
        }));
    }

    #[test]
    fn cancelled_request_markers_are_hard_bounded() {
        let _guard = CANCELLATION_TEST_LOCK.lock().unwrap();
        let mut cancelled = CANCELLED_REQUESTS.lock().unwrap();
        cancelled.clear();
        for index in 0..MAX_CANCELLED_REQUESTS {
            cancelled.insert(format!("value-scan-bounded-{index:04}"));
        }
        drop(cancelled);
        let err = value_scan_cancel_request("value-scan-bounded-overflow".to_string())
            .expect_err("overflow cancellation rejected");
        assert!(err.contains("Too many pending"));
        CANCELLED_REQUESTS.lock().unwrap().clear();
    }

    #[test]
    fn exact_scan_finds_unaligned_and_negative_i32_values() {
        let mut bytes = vec![0xAA];
        bytes.extend_from_slice(&(-42i32).to_le_bytes());
        bytes.push(0xBB);
        let mut matches = Vec::new();
        assert!(scan_i32_exact(&bytes, 0x1000, -42, &mut matches));
        assert_eq!(matches, vec![(0x1001, -42)]);
    }

    #[test]
    fn request_requires_authorization_and_bounded_budget() {
        let request = ValueScanRequest {
            value: 1,
            max_scan_bytes: None,
            authorized: false,
            request_id: "value-scan-test-0001".to_string(),
        };
        assert!(validate_request(7, &request)
            .unwrap_err()
            .contains("authorized"));
        let request = ValueScanRequest {
            value: 1,
            max_scan_bytes: Some(MAX_SCAN_BYTES + 1),
            authorized: true,
            request_id: "value-scan-test-0002".to_string(),
        };
        assert!(validate_request(7, &request).is_err());
        assert!(validate_request(
            0,
            &ValueScanRequest {
                value: 1,
                max_scan_bytes: None,
                authorized: true,
                request_id: "value-scan-test-0003".to_string()
            }
        )
        .is_err());
    }

    #[test]
    fn addresses_are_serialized_without_javascript_precision_loss() {
        assert_eq!(format_address(0xFFFF_FFFF_FFFF_FFFF), "0xFFFFFFFFFFFFFFFF");
    }

    #[test]
    fn cancelled_request_marker_is_consumed_without_creating_a_session() {
        let _guard = CANCELLATION_TEST_LOCK.lock().unwrap();
        let request_id = "value-scan-cancel-race-test".to_string();
        value_scan_cancel_request(request_id.clone())
            .expect("cancellation marker should be accepted");
        assert!(CANCELLED_REQUESTS.lock().unwrap().remove(&request_id));
        assert!(VALUE_SCAN_SESSIONS
            .lock()
            .unwrap()
            .values()
            .all(|session| session.request_id != request_id));
    }

    #[test]
    fn address_parser_requires_explicit_hex_notation() {
        assert_eq!(parse_address("0x0000000000001234").unwrap(), 0x1234);
        assert!(parse_address("4660").is_err());
        assert!(parse_address("0xnot-hex").is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn read_only_windows_scan_finds_value_in_current_owned_process() {
        use std::sync::atomic::AtomicI32;
        static OWNED_TEST_VALUE: AtomicI32 = AtomicI32::new(0x1357_9BDF);

        let expected_address = (&OWNED_TEST_VALUE as *const AtomicI32) as u64;
        let session = start_windows_scan(
            std::process::id(),
            0x1357_9BDF,
            64 * 1024 * 1024,
            "value-scan-self-test".to_string(),
        )
        .expect("read-only self-process scan should be available during the Windows test");
        assert!(
            session
                .candidates
                .iter()
                .any(|(address, _)| *address == expected_address),
            "the scanner must find the exact owned static allocation"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn exact_edit_is_verified_and_rollback_restores_owned_value() {
        use std::sync::atomic::{AtomicI32, Ordering};
        use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };
        static OWNED_EDIT_VALUE: AtomicI32 = AtomicI32::new(123_456_789);
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                std::process::id(),
            )
        };
        assert_ne!(process, 0);
        let creation_key = read_process_creation_key(process).unwrap();
        unsafe { CloseHandle(process) };
        let edit = PendingValueEdit {
            scan_id: 1,
            pid: std::process::id(),
            process_name: "hexhawk-backend-test".to_string(),
            process_creation_key: creation_key,
            address: (&OWNED_EDIT_VALUE as *const AtomicI32) as u64,
            original_value: 123_456_789,
            new_value: 123_456_790,
            expires_at: Instant::now() + EDIT_PREVIEW_TTL,
            written: false,
        };
        assert_eq!(
            write_i32_checked(&edit, edit.original_value, edit.new_value).unwrap(),
            edit.new_value
        );
        assert_eq!(OWNED_EDIT_VALUE.load(Ordering::SeqCst), edit.new_value);
        assert_eq!(
            write_i32_checked(&edit, edit.new_value, edit.original_value).unwrap(),
            edit.original_value
        );
        assert_eq!(OWNED_EDIT_VALUE.load(Ordering::SeqCst), edit.original_value);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn freeze_enforces_owned_value_and_stops_with_safe_restore() {
        let _freeze_test_guard = FREEZE_TEST_LOCK.lock().unwrap();
        use std::sync::atomic::{AtomicI32, Ordering};
        use windows_sys::Win32::Foundation::FALSE;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };
        static OWNED_FREEZE_VALUE: AtomicI32 = AtomicI32::new(81_234_567);
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                std::process::id(),
            )
        };
        assert_ne!(process, 0);
        let scan_id = next_scan_id();
        let address = (&OWNED_FREEZE_VALUE as *const AtomicI32) as u64;
        VALUE_SCAN_SESSIONS.lock().unwrap().insert(
            scan_id,
            ValueScanSession {
                request_id: "owned-freeze-value-test".to_string(),
                pid: std::process::id(),
                process_name: "hexhawk-backend-test".to_string(),
                process_creation_key: read_process_creation_key(process).unwrap(),
                candidates: vec![(address, 81_234_567)],
                scanned_bytes: 4,
                scanned_regions: 1,
                complete: true,
                warnings: Vec::new(),
                process,
            },
        );
        let preview = value_freeze_preview(ValueFreezePreviewRequest {
            scan_id,
            address: format_address(address),
            frozen_value: 81_234_568,
            authorized: true,
            interval_milliseconds: Some(50),
        })
        .unwrap();
        let preview_interval_milliseconds = preview.interval_milliseconds;
        let active = value_freeze_commit(ValueFreezeCommitRequest {
            confirmation_token: preview.confirmation_token,
        })
        .unwrap();
        assert!(active.active);
        assert_eq!(OWNED_FREEZE_VALUE.load(Ordering::SeqCst), 81_234_568);
        OWNED_FREEZE_VALUE.store(7, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(preview_interval_milliseconds + 100));
        assert_eq!(OWNED_FREEZE_VALUE.load(Ordering::SeqCst), 81_234_568);
        let stopped = value_freeze_stop(ValueFreezeStopRequest {
            freeze_id: active.freeze_id.clone(),
            restore_original: true,
        })
        .unwrap();
        assert!(!stopped.active);
        assert!(stopped.restored_original);
        assert_eq!(OWNED_FREEZE_VALUE.load(Ordering::SeqCst), 81_234_567);
        assert!(value_freeze_status(active.freeze_id).is_ok());
        VALUE_SCAN_SESSIONS.lock().unwrap().remove(&scan_id);
    }

    #[test]
    fn freeze_worker_admission_is_atomic_bounded_and_candidate_unique() {
        let _freeze_test_guard = FREEZE_TEST_LOCK.lock().unwrap();
        let pending = |pid, address| PendingValueFreeze {
            scan_id: pid,
            pid,
            process_name: "owned-freeze-admission-test".to_string(),
            process_creation_key: u64::from(pid) + 100,
            address,
            original_value: 1,
            frozen_value: 2,
            interval: Duration::from_millis(50),
            expires_at: Instant::now() + FREEZE_PREVIEW_TTL,
        };
        let first = FreezeWorkerPermit::acquire(&pending(10_001, 0x1000)).unwrap();
        assert!(FreezeWorkerPermit::acquire(&pending(10_001, 0x1000))
            .unwrap_err()
            .contains("already has an active freeze"));
        let second = FreezeWorkerPermit::acquire(&pending(10_002, 0x2000)).unwrap();
        let third = FreezeWorkerPermit::acquire(&pending(10_003, 0x3000)).unwrap();
        let fourth = FreezeWorkerPermit::acquire(&pending(10_004, 0x4000)).unwrap();
        assert!(FreezeWorkerPermit::acquire(&pending(10_005, 0x5000))
            .unwrap_err()
            .contains("Too many value freezes"));
        drop((first, second, third, fourth));
        assert_eq!(ACTIVE_FREEZE_WORKERS.load(Ordering::Acquire), 0);
        assert!(ACTIVE_FREEZE_TARGETS.lock().unwrap().is_empty());
    }

    #[test]
    fn freeze_cadence_accepts_responsive_game_intervals_and_rejects_extremes() {
        assert_eq!(freeze_interval(50).unwrap(), Duration::from_millis(50));
        assert_eq!(freeze_interval(100).unwrap(), Duration::from_millis(100));
        assert_eq!(freeze_interval(250).unwrap(), Duration::from_millis(250));
        assert!(freeze_interval(10).is_err());
        assert!(freeze_interval(2_000).is_err());
    }

    #[test]
    fn freeze_tolerates_transient_target_overwrites_but_stops_after_repeated_failures() {
        let retention_error =
            "Write verification failed; the target did not retain the requested value.";
        for failures in 1..MAX_CONSECUTIVE_FREEZE_FAILURES {
            assert!(!should_stop_freeze_after_failure(retention_error, failures));
        }
        assert!(should_stop_freeze_after_failure(
            retention_error,
            MAX_CONSECUTIVE_FREEZE_FAILURES
        ));
        assert!(should_stop_freeze_after_failure(
            "Target process identity changed; freeze stopped.",
            1
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires an explicitly authorized live target PID and value"]
    fn authorized_external_scan_probe() {
        let pid = std::env::var("HEXHAWK_AUTHORIZED_TARGET_PID")
            .expect("set HEXHAWK_AUTHORIZED_TARGET_PID")
            .parse::<u32>()
            .expect("target PID must be decimal u32");
        let value = std::env::var("HEXHAWK_AUTHORIZED_TARGET_I32")
            .expect("set HEXHAWK_AUTHORIZED_TARGET_I32")
            .parse::<i32>()
            .expect("target value must be decimal i32");
        let session = start_windows_scan(
            pid,
            value,
            MAX_SCAN_BYTES,
            "authorized-external-scan-probe".to_string(),
        )
        .expect("authorized target scan must complete");
        assert!(session.scanned_bytes > 0, "scanner must read target memory");
        let expected_address = std::env::var("HEXHAWK_AUTHORIZED_EXPECTED_ADDRESS")
            .ok()
            .map(|address| {
                parse_address(&address).expect("expected address must be canonical hex")
            });
        if let Some(expected_address) = expected_address {
            assert!(
                session
                    .candidates
                    .iter()
                    .any(|(address, _)| *address == expected_address),
                "the scanner must retain the authorized expected address"
            );
        }
        eprintln!(
            "authorized external scan: process={} pid={} value={} regions={} bytes={} candidates={} complete={} expected_address_found={}",
            session.process_name,
            session.pid,
            value,
            session.scanned_regions,
            session.scanned_bytes,
            session.candidates.len(),
            session.complete,
            expected_address.is_some()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires an explicitly authorized live target PID, value, and address"]
    fn authorized_external_edit_preview_probe() {
        let pid = std::env::var("HEXHAWK_AUTHORIZED_TARGET_PID")
            .expect("set HEXHAWK_AUTHORIZED_TARGET_PID")
            .parse::<u32>()
            .expect("target PID must be decimal u32");
        let value = std::env::var("HEXHAWK_AUTHORIZED_TARGET_I32")
            .expect("set HEXHAWK_AUTHORIZED_TARGET_I32")
            .parse::<i32>()
            .expect("target value must be decimal i32");
        let new_value = std::env::var("HEXHAWK_AUTHORIZED_REPLACEMENT_I32")
            .expect("set HEXHAWK_AUTHORIZED_REPLACEMENT_I32")
            .parse::<i32>()
            .expect("replacement value must be decimal i32");
        let address = std::env::var("HEXHAWK_AUTHORIZED_EXPECTED_ADDRESS")
            .expect("set HEXHAWK_AUTHORIZED_EXPECTED_ADDRESS");
        let scan_id = next_scan_id();
        let session = start_windows_scan(
            pid,
            value,
            MAX_SCAN_BYTES,
            "authorized-external-edit-preview".to_string(),
        )
        .expect("authorized target scan must complete");
        assert!(
            session
                .candidates
                .iter()
                .any(|(candidate, _)| *candidate == parse_address(&address).unwrap()),
            "preview address must be retained by the exact scan"
        );
        VALUE_SCAN_SESSIONS.lock().unwrap().insert(scan_id, session);
        let preview = value_edit_preview(ValueEditPreviewRequest {
            scan_id,
            address,
            new_value,
            authorized: true,
        })
        .expect("authorized edit preview must succeed");
        assert_eq!(preview.original_value, value);
        assert_eq!(preview.new_value, new_value);
        assert_eq!(
            read_i32(
                VALUE_SCAN_SESSIONS.lock().unwrap()[&scan_id].process,
                parse_address(&preview.address).unwrap()
            )
            .unwrap(),
            value,
            "preview must not mutate target memory"
        );
        PENDING_VALUE_EDITS
            .lock()
            .unwrap()
            .remove(&preview.confirmation_token);
        VALUE_SCAN_SESSIONS.lock().unwrap().remove(&scan_id);
        eprintln!(
            "authorized edit preview: process={} pid={} address={} old={} new={} old_bytes={:02X?} new_bytes={:02X?} expires={}s authority={}",
            preview.process_name,
            preview.pid,
            preview.address,
            preview.original_value,
            preview.new_value,
            preview.original_bytes_le,
            preview.new_bytes_le,
            preview.expires_in_seconds,
            preview.authority
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires explicit authorization and an interactive rollback acknowledgement"]
    fn authorized_external_edit_roundtrip_probe() {
        use std::io;
        let pid = std::env::var("HEXHAWK_AUTHORIZED_TARGET_PID")
            .expect("set HEXHAWK_AUTHORIZED_TARGET_PID")
            .parse::<u32>()
            .expect("target PID must be decimal u32");
        let value = std::env::var("HEXHAWK_AUTHORIZED_TARGET_I32")
            .expect("set HEXHAWK_AUTHORIZED_TARGET_I32")
            .parse::<i32>()
            .expect("target value must be decimal i32");
        let new_value = std::env::var("HEXHAWK_AUTHORIZED_REPLACEMENT_I32")
            .expect("set HEXHAWK_AUTHORIZED_REPLACEMENT_I32")
            .parse::<i32>()
            .expect("replacement value must be decimal i32");
        let address = std::env::var("HEXHAWK_AUTHORIZED_EXPECTED_ADDRESS")
            .expect("set HEXHAWK_AUTHORIZED_EXPECTED_ADDRESS");
        assert_eq!(
            std::env::var("HEXHAWK_AUTHORIZED_CONFIRMATION").as_deref(),
            Ok("EDIT"),
            "set HEXHAWK_AUTHORIZED_CONFIRMATION=EDIT"
        );
        let scan_id = next_scan_id();
        let session = start_windows_scan(
            pid,
            value,
            MAX_SCAN_BYTES,
            "authorized-external-edit-roundtrip".to_string(),
        )
        .expect("authorized target scan must complete");
        assert!(
            session
                .candidates
                .iter()
                .any(|(candidate, _)| *candidate == parse_address(&address).unwrap()),
            "edit address must be retained by the exact scan"
        );
        VALUE_SCAN_SESSIONS.lock().unwrap().insert(scan_id, session);
        let preview = value_edit_preview(ValueEditPreviewRequest {
            scan_id,
            address,
            new_value,
            authorized: true,
        })
        .expect("authorized edit preview must succeed");
        let result = value_edit_commit(ValueEditCommitRequest {
            confirmation_token: preview.confirmation_token,
        })
        .expect("authorized edit commit must succeed");
        let rollback_token = result
            .rollback_token
            .clone()
            .expect("verified edit must provide rollback");
        eprintln!(
            "EDIT VERIFIED: process={} pid={} address={} old={} current={} authority={}. Press Enter to roll back.",
            result.process_name,
            result.pid,
            result.address,
            result.original_value,
            result.current_value,
            result.authority
        );
        let mut acknowledgement = String::new();
        io::stdin()
            .read_line(&mut acknowledgement)
            .expect("rollback acknowledgement must be readable");
        let rollback = value_edit_rollback(rollback_token).expect("rollback must succeed");
        assert_eq!(rollback.current_value, value);
        eprintln!(
            "ROLLBACK VERIFIED: process={} pid={} address={} restored={} authority={}",
            rollback.process_name,
            rollback.pid,
            rollback.address,
            rollback.current_value,
            rollback.authority
        );
        VALUE_SCAN_SESSIONS.lock().unwrap().remove(&scan_id);
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires explicit authorization for one exact external write"]
    fn authorized_external_exact_write_probe() {
        let pid = std::env::var("HEXHAWK_AUTHORIZED_TARGET_PID")
            .expect("set HEXHAWK_AUTHORIZED_TARGET_PID")
            .parse::<u32>()
            .expect("target PID must be decimal u32");
        let value = std::env::var("HEXHAWK_AUTHORIZED_TARGET_I32")
            .expect("set HEXHAWK_AUTHORIZED_TARGET_I32")
            .parse::<i32>()
            .expect("target value must be decimal i32");
        let new_value = std::env::var("HEXHAWK_AUTHORIZED_REPLACEMENT_I32")
            .expect("set HEXHAWK_AUTHORIZED_REPLACEMENT_I32")
            .parse::<i32>()
            .expect("replacement value must be decimal i32");
        let address = std::env::var("HEXHAWK_AUTHORIZED_EXPECTED_ADDRESS")
            .expect("set HEXHAWK_AUTHORIZED_EXPECTED_ADDRESS");
        assert_eq!(
            std::env::var("HEXHAWK_AUTHORIZED_CONFIRMATION").as_deref(),
            Ok("EDIT"),
            "set HEXHAWK_AUTHORIZED_CONFIRMATION=EDIT"
        );
        let scan_id = next_scan_id();
        let session = start_windows_scan(
            pid,
            value,
            MAX_SCAN_BYTES,
            "authorized-external-exact-write".to_string(),
        )
        .expect("authorized target scan must complete");
        assert!(
            session
                .candidates
                .iter()
                .any(|(candidate, _)| *candidate == parse_address(&address).unwrap()),
            "write address must be retained by the exact scan"
        );
        VALUE_SCAN_SESSIONS.lock().unwrap().insert(scan_id, session);
        let preview = value_edit_preview(ValueEditPreviewRequest {
            scan_id,
            address,
            new_value,
            authorized: true,
        })
        .expect("authorized edit preview must succeed");
        let result = value_edit_commit(ValueEditCommitRequest {
            confirmation_token: preview.confirmation_token,
        })
        .expect("authorized exact write must succeed");
        assert_eq!(result.current_value, new_value);
        if let Some(token) = result.rollback_token {
            PENDING_VALUE_EDITS.lock().unwrap().remove(&token);
        }
        VALUE_SCAN_SESSIONS.lock().unwrap().remove(&scan_id);
        eprintln!(
            "EXACT WRITE VERIFIED: process={} pid={} address={} old={} current={} authority={}",
            result.process_name,
            result.pid,
            result.address,
            result.original_value,
            result.current_value,
            result.authority
        );
    }
}
