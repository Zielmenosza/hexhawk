// src-tauri/src/commands/run_plugins.rs

use std::{
    fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};
use crate::plugins::{get_all_plugins, get_user_plugin_dir, scan_plugin_dir};
use plugin_api::{Plugin, PluginKind, PluginResult, PLUGIN_EXECUTION_TIMEOUT_SECS, PLUGIN_RESULT_MAX_JSON_BYTES};
use serde::Serialize;
use tauri::command;
use sha2::{Sha256, Digest};

#[derive(Debug, Serialize)]
pub struct PluginResultResponse {
    pub schema_version: u32,
    pub plugin: String,
    pub version: String,
    pub description: String,
    pub success: bool,
    pub summary: String,
    pub details: Option<serde_json::Value>,
    pub kind: PluginKind,
    pub plugin_hash: Option<String>,
}

const MAX_INFLIGHT_PLUGIN_WORKERS: usize = 8;
static ACTIVE_PLUGIN_WORKERS: AtomicUsize = AtomicUsize::new(0);

fn try_acquire_plugin_worker_slot() -> bool {
    loop {
        let current = ACTIVE_PLUGIN_WORKERS.load(Ordering::SeqCst);
        if current >= MAX_INFLIGHT_PLUGIN_WORKERS {
            return false;
        }
        if ACTIVE_PLUGIN_WORKERS
            .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return true;
        }
    }
}

#[cfg(test)]
fn active_plugin_workers() -> usize {
    ACTIVE_PLUGIN_WORKERS.load(Ordering::SeqCst)
}

struct PluginWorkerGuard;

impl Drop for PluginWorkerGuard {
    fn drop(&mut self) {
        ACTIVE_PLUGIN_WORKERS.fetch_sub(1, Ordering::SeqCst);
    }
}

fn execute_plugin_with_timeout(plugin: Box<dyn Plugin>, data: Arc<Vec<u8>>, timeout: Duration) -> Result<PluginResult, String> {
    let plugin_name = plugin.name().to_string();
    if !try_acquire_plugin_worker_slot() {
        return Err(format!(
            "Plugin worker capacity reached ({} in-flight workers).",
            MAX_INFLIGHT_PLUGIN_WORKERS
        ));
    }

    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let _guard = PluginWorkerGuard;
        let result = plugin.run(&data);
        let _ = sender.send(result);
    });

    receiver.recv_timeout(timeout).map_err(|_| {
        format!(
            "Plugin '{}' timed out after {} seconds",
            plugin_name,
            timeout.as_secs()
        )
    })
}

/// Compute SHA256 hash of plugin result JSON for change detection and caching.
/// Returns first 16 hex characters (8 bytes) for readability.
fn compute_result_hash(json_str: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(json_str.as_bytes());
    let hash = hasher.finalize();
    format!("{:x}", hash)[..16].to_string()
}

const MAX_FILE_SIZE_BYTES: usize = 512 * 1024 * 1024; // 512 MB

fn validate_input_file(path: &str) -> Result<std::path::PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|e| format!("Invalid file path: {e}"))?;

    let meta = fs::metadata(&canonical)
        .map_err(|e| format!("Failed to stat file: {e}"))?;

    if !meta.is_file() {
        return Err("Input path must be a regular file.".to_string());
    }

    if meta.len() as usize > MAX_FILE_SIZE_BYTES {
        return Err(format!(
            "File exceeds maximum allowed size of {} MB ({} bytes). Use a smaller file or a split range.",
            MAX_FILE_SIZE_BYTES / (1024 * 1024),
            meta.len()
        ));
    }

    Ok(canonical)
}

#[command]
pub async fn run_plugins_on_file(app: tauri::AppHandle, path: String) -> Result<Vec<PluginResultResponse>, String> {
    let canonical_path = validate_input_file(&path)?;
    let file_bytes = fs::read(&canonical_path).map_err(|e| format!("Failed to read file: {}", e))?;
    let data = Arc::new(file_bytes);

    // Collect built-in plugins and user plugins into one list.
    let mut plugins: Vec<Box<dyn Plugin>> = get_all_plugins();
    if let Ok(user_dir) = get_user_plugin_dir(&app) {
        for (_info, maybe_plugin) in scan_plugin_dir(&user_dir) {
            if let Some(plugin) = maybe_plugin {
                plugins.push(plugin);
            }
        }
    }

    let mut results = Vec::new();
    let timeout = Duration::from_secs(PLUGIN_EXECUTION_TIMEOUT_SECS);

    for plugin in plugins {
        let plugin_name = plugin.name().to_string();
        let plugin_version = plugin.version().to_string();
        let plugin_description = plugin.description().to_string();
        let mut result = match execute_plugin_with_timeout(plugin, Arc::clone(&data), timeout) {
            Ok(result) => {
                let payload = result.to_json();
                if let Err(size_error) = PluginResult::validate_json_size(&payload) {
                    PluginResult::error_with_details(
                        plugin_name.clone(),
                        plugin_version.clone(),
                        size_error,
                        serde_json::json!({ "max_size": PLUGIN_RESULT_MAX_JSON_BYTES }),
                        PluginKind::Error,
                    )
                } else {
                    result
                }
            }
            Err(error) => PluginResult::error_with_details(
                plugin_name.clone(),
                plugin_version.clone(),
                error,
                serde_json::json!({ "timeout_seconds": timeout.as_secs() }),
                PluginKind::Error,
            ),
        };

        // Compute hash of the result JSON for change detection and caching.
        let result_json = result.to_json();
        let result_hash = compute_result_hash(&result_json);
        result = result.with_hash(Some(result_hash));

        results.push(PluginResultResponse {
            schema_version: result.schema_version,
            plugin: result.plugin,
            version: result.version,
            description: plugin_description,
            success: result.success,
            summary: result.summary,
            details: result.details,
            kind: result.kind,
            plugin_hash: result.plugin_hash,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
        static TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
        TEST_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("test lock poisoned")
    }

    struct QuickPlugin;

    impl Plugin for QuickPlugin {
        fn name(&self) -> &'static str {
            "quick"
        }

        fn run(&self, _data: &[u8]) -> PluginResult {
            PluginResult::success(self.name(), self.version(), "ok", self.kind())
        }
    }

    struct SleepingPlugin {
        name: &'static str,
        sleep_ms: u64,
    }

    impl Plugin for SleepingPlugin {
        fn name(&self) -> &'static str {
            self.name
        }

        fn run(&self, _data: &[u8]) -> PluginResult {
            std::thread::sleep(Duration::from_millis(self.sleep_ms));
            PluginResult::success(self.name(), self.version(), "done", self.kind())
        }
    }

    #[test]
    fn validate_input_file_rejects_missing() {
        let err = validate_input_file("this-file-should-not-exist.bin").unwrap_err();
        assert!(err.contains("Invalid file path") || err.contains("Failed to stat file"));
    }

    #[test]
    fn validate_input_file_accepts_regular_file() {
        let tmp = std::env::temp_dir().join("hexhawk_run_plugins_validate.tmp");
        std::fs::write(&tmp, b"abc").expect("write temp file");
        let result = validate_input_file(tmp.to_string_lossy().as_ref());
        let _ = std::fs::remove_file(&tmp);
        assert!(result.is_ok());
    }

    #[test]
    fn execute_plugin_with_timeout_releases_slot_after_success() {
        let _lock = lock_tests();
        let data = Arc::new(vec![1, 2, 3]);

        let result = execute_plugin_with_timeout(
            Box::new(QuickPlugin),
            Arc::clone(&data),
            Duration::from_millis(200),
        );

        assert!(result.is_ok());
        assert_eq!(active_plugin_workers(), 0);
    }

    #[test]
    fn execute_plugin_with_timeout_enforces_worker_cap_after_timeouts() {
        let _lock = lock_tests();
        let data = Arc::new(vec![0; 64]);
        let names = [
            "sleep-0", "sleep-1", "sleep-2", "sleep-3",
            "sleep-4", "sleep-5", "sleep-6", "sleep-7",
        ];

        for idx in 0..MAX_INFLIGHT_PLUGIN_WORKERS {
            let plugin = SleepingPlugin {
                name: names[idx],
                sleep_ms: 200,
            };
            let result = execute_plugin_with_timeout(
                Box::new(plugin),
                Arc::clone(&data),
                Duration::from_millis(5),
            );
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("timed out"));
        }

        let blocked = execute_plugin_with_timeout(
            Box::new(SleepingPlugin {
                name: "overflow",
                sleep_ms: 200,
            }),
            Arc::clone(&data),
            Duration::from_millis(5),
        );

        assert!(blocked.is_err());
        assert!(blocked
            .unwrap_err()
            .contains("Plugin worker capacity reached"));

        std::thread::sleep(Duration::from_millis(280));
        assert_eq!(active_plugin_workers(), 0);
    }
}
