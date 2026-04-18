use crate::plugins::get_all_plugins;
use libloading::Library;
use once_cell::sync::Lazy;
use std::{collections::HashMap, path::{Path, PathBuf}, sync::Mutex};
use super::inspect::PluginMetadata;
use tauri::command;

static PLUGIN_LIBRARIES: Lazy<Mutex<HashMap<String, Library>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn plugin_library_extensions() -> &'static [&'static str] {
    if cfg!(target_os = "windows") {
        &["dll"]
    } else if cfg!(target_os = "macos") {
        &["dylib"]
    } else {
        &["so"]
    }
}

fn discover_plugin_path(name: &str) -> Option<PathBuf> {
    let base = Path::new("plugins").join(name).join("target").join("debug");
    for ext in plugin_library_extensions() {
        let file_name = if cfg!(target_os = "windows") {
            format!("{name}.{ext}")
        } else {
            format!("lib{name}.{ext}")
        };
        let candidate = base.join(file_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[command]
pub async fn list_available_plugins() -> Result<Vec<PluginMetadata>, String> {
    let plugins = get_all_plugins();
    let mut results = Vec::new();

    for plugin in plugins {
        results.push(PluginMetadata {
            name: plugin.name().to_string(),
            description: plugin.description().to_string(),
            version: Some(plugin.version().to_string()),
            enabled: true,
            path: None,
        });
    }

    Ok(results)
}

#[command]
pub fn reload_plugin(name: String) -> Result<(), String> {
    let plugins = get_all_plugins();
    let _plugin = plugins
        .into_iter()
        .find(|plugin| plugin.name() == name)
        .ok_or_else(|| format!("Plugin not found: {}", name))?;

    let path = discover_plugin_path(&name)
        .ok_or_else(|| format!("Could not resolve path for plugin: {}", name))?;

    if !path.exists() {
        return Err(format!("Plugin library not found at {}", path.display()));
    }

    let mut libraries = PLUGIN_LIBRARIES
        .lock()
        .map_err(|e| format!("Failed to lock plugin registry: {}", e))?;
    libraries.remove(&name);

    let library = unsafe { Library::new(&path) }
        .map_err(|err| format!("Failed to reload plugin {}: {}", name, err))?;
    libraries.insert(name, library);

    Ok(())
}
