// src-tauri/src/commands/run_plugins.rs

use std::{fs, sync::{mpsc, Arc}, thread, time::Duration};
use crate::plugins::get_all_plugins;
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

fn execute_plugin_with_timeout(plugin: Box<dyn Plugin>, data: Arc<Vec<u8>>, timeout: Duration) -> Result<PluginResult, String> {
    let plugin_name = plugin.name().to_string();
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
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

#[command]
pub async fn run_plugins_on_file(path: String) -> Result<Vec<PluginResultResponse>, String> {
    let file_bytes = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    if file_bytes.len() > MAX_FILE_SIZE_BYTES {
        return Err(format!(
            "File exceeds maximum allowed size of {} MB ({} bytes). Use a smaller file or a split range.",
            MAX_FILE_SIZE_BYTES / (1024 * 1024),
            file_bytes.len()
        ));
    }
    let data = Arc::new(file_bytes);
    let plugins = get_all_plugins();
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
