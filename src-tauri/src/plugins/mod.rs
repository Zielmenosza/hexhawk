// src-tauri/src/plugins/mod.rs

use plugin_api::{Plugin, PluginResult};
use std::path::{Path, PathBuf};

pub struct ByteCounter;

impl Plugin for ByteCounter {
    fn name(&self) -> &'static str {
        "ByteCounter"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn description(&self) -> &'static str {
        "Counts the number of bytes in the input"
    }

    fn run(&self, data: &[u8]) -> PluginResult {
        self.success_with_details(
            format!("{} bytes", data.len()),
            serde_json::json!({ "byte_count": data.len() }),
        )
    }
}

pub fn get_all_plugins() -> Vec<Box<dyn Plugin>> {
    vec![Box::new(ByteCounter)]
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UserPluginInfo {
    pub filename: String,
    pub path: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub load_error: Option<String>,
}

// Temporary compatibility fallback: dynamic user plugins disabled when QUILL
// module source is not present in this branch.
pub fn scan_plugin_dir(_dir: &Path) -> Vec<(UserPluginInfo, Option<Box<dyn Plugin>>)> {
    vec![]
}

pub fn get_user_plugin_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    use tauri::Manager;
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Cannot determine app data directory: {e}"))?;
    let plugins_dir = data_dir.join("plugins");
    std::fs::create_dir_all(&plugins_dir)
        .map_err(|e| format!("Cannot create plugin directory: {e}"))?;
    Ok(plugins_dir)
}

pub fn evict_from_cache(_path: &Path) {}