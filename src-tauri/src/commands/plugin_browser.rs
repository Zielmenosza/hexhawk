use crate::plugins::{evict_from_cache, get_all_plugins, get_user_plugin_dir, scan_plugin_dir, UserPluginInfo};
use std::fs::OpenOptions;
use std::io;
use std::path::Path;
use super::inspect::PluginMetadata;
use tauri::command;

fn copy_file_create_new(src: &Path, dest: &Path) -> Result<(), String> {
    let mut src_file = std::fs::File::open(src)
        .map_err(|e| format!("Failed to open source plugin: {e}"))?;
    let mut dest_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dest)
        .map_err(|e| format!("Failed to create destination plugin: {e}"))?;
    io::copy(&mut src_file, &mut dest_file)
        .map_err(|e| format!("Failed to copy plugin bytes: {e}"))?;
    Ok(())
}

const MAX_PLUGIN_BINARY_BYTES: u64 = 64 * 1024 * 1024;

fn allowed_plugin_extensions() -> &'static [&'static str] {
    if cfg!(target_os = "windows") {
        &["dll"]
    } else if cfg!(target_os = "macos") {
        &["dylib"]
    } else {
        &["so"]
    }
}

fn has_allowed_plugin_extension(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    allowed_plugin_extensions().contains(&ext.as_str())
}

fn validate_uninstall_filename(filename: &str) -> Result<String, String> {
    let safe_name = Path::new(filename)
        .file_name()
        .ok_or_else(|| "Invalid filename — no path separators allowed".to_string())?
        .to_string_lossy()
        .to_string();

    if safe_name != filename {
        return Err("Invalid filename — no path separators allowed".to_string());
    }
    if !has_allowed_plugin_extension(Path::new(&safe_name)) {
        return Err(format!(
            "Unsupported extension. Expected: {}",
            allowed_plugin_extensions().join(", ")
        ));
    }
    Ok(safe_name)
}

// ─── List all plugins (built-in + user) ──────────────────────────────────────

#[command]
pub async fn list_available_plugins(app: tauri::AppHandle) -> Result<Vec<PluginMetadata>, String> {
    let mut results = Vec::new();

    // Built-in plugins
    for plugin in get_all_plugins() {
        results.push(PluginMetadata {
            name: plugin.name().to_string(),
            description: plugin.description().to_string(),
            version: Some(plugin.version().to_string()),
            enabled: true,
            path: None,
        });
    }

    // User plugins (best-effort — errors are surfaced in list_user_plugins)
    if let Ok(dir) = get_user_plugin_dir(&app) {
        for (info, _) in scan_plugin_dir(&dir) {
            if info.load_error.is_none() {
                results.push(PluginMetadata {
                    name: info.name,
                    description: info.description,
                    version: Some(info.version),
                    enabled: true,
                    path: Some(info.path),
                });
            }
        }
    }

    Ok(results)
}

/// reload_plugin is kept for backward compatibility; it is a no-op for
/// built-in plugins and re-scans the user directory for dynamic ones.
#[command]
pub async fn reload_plugin(_name: String) -> Result<(), String> {
    // Built-in plugins are compiled in and cannot be reloaded.
    // User plugins are loaded fresh on every analysis run via scan_plugin_dir.
    Ok(())
}

// ─── User plugin management commands ─────────────────────────────────────────

/// Return the absolute path to the user plugin directory.
#[command]
pub async fn get_plugin_directory(app: tauri::AppHandle) -> Result<String, String> {
    let dir = get_user_plugin_dir(&app)?;
    Ok(dir.to_string_lossy().to_string())
}

/// Enumerate all user-plugin DLLs and their load status.
#[command]
pub async fn list_user_plugins(app: tauri::AppHandle) -> Result<Vec<UserPluginInfo>, String> {
    let dir = get_user_plugin_dir(&app)?;
    let results = scan_plugin_dir(&dir);
    Ok(results.into_iter().map(|(info, _)| info).collect())
}

/// Copy `src_path` into the user plugin directory and validate it loads.
/// If validation fails the copy is deleted and an error is returned.
#[command]
pub async fn install_plugin(
    app: tauri::AppHandle,
    src_path: String,
) -> Result<UserPluginInfo, String> {
    let src_canonical = std::fs::canonicalize(&src_path)
        .map_err(|e| format!("Invalid source path: {e}"))?;
    let src = src_canonical.as_path();

    let src_meta = std::fs::metadata(src)
        .map_err(|e| format!("Failed to stat source path: {e}"))?;
    if !src_meta.is_file() {
        return Err("Source plugin path must be a regular file".to_string());
    }

    // ── Extension whitelist ───────────────────────────────────────────────────
    if !has_allowed_plugin_extension(src) {
        return Err(format!(
            "Unsupported extension. Expected: {}",
            allowed_plugin_extensions().join(", ")
        ));
    }

    if src_meta.len() > MAX_PLUGIN_BINARY_BYTES {
        return Err(format!(
            "Plugin binary exceeds maximum allowed size of {} MB",
            MAX_PLUGIN_BINARY_BYTES / (1024 * 1024)
        ));
    }

    let filename = src
        .file_name()
        .ok_or_else(|| "Source path has no filename".to_string())?;

    let dir = get_user_plugin_dir(&app)?;
    let dest = dir.join(filename);

    if dest.exists() {
        return Err("A plugin with the same filename already exists. Remove it first to replace.".to_string());
    }

    copy_file_create_new(src, &dest)?;

    // ── Validate the copied file actually loads as a HexHawk plugin ──────────
    match crate::plugins::quill::scan_plugin_dir(&dir)
        .into_iter()
        .find(|(info, _)| {
            info.filename == filename.to_string_lossy().as_ref()
        }) {
        Some((info, Some(_))) => Ok(info),
        Some((info, None)) => {
            // Remove the invalid file so it doesn't permanently break the dir.
            let _ = std::fs::remove_file(&dest);
            Err(format!(
                "Plugin failed to load: {}",
                info.load_error.unwrap_or_default()
            ))
        }
        None => {
            let _ = std::fs::remove_file(&dest);
            Err("Plugin was copied but could not be verified".to_string())
        }
    }
}
/// Delete a user plugin from the plugin directory.
///
/// `filename` must be a bare filename (no directory separators) to prevent
/// path-traversal attacks.
#[command]
pub async fn uninstall_plugin(
    app: tauri::AppHandle,
    filename: String,
) -> Result<(), String> {
    // ── Path traversal + extension guard ─────────────────────────────────────
    let safe_name = validate_uninstall_filename(&filename)?;

    let dir = get_user_plugin_dir(&app)?;
    let path = dir.join(&safe_name);

    if !path.exists() {
        return Err(format!("Plugin '{}' does not exist", filename));
    }

    let meta = std::fs::metadata(&path)
        .map_err(|e| format!("Failed to stat plugin path: {e}"))?;
    if !meta.is_file() {
        return Err("Target plugin path is not a regular file".to_string());
    }

    // Confirm the resolved path is still inside the plugin directory.
    let canonical_dir = dir
        .canonicalize()
        .map_err(|e| format!("Cannot resolve plugin directory: {e}"))?;
    // path may not exist yet if we're cleaning up a failed load
    let canonical_path = path
        .canonicalize()
        .unwrap_or_else(|_| path.clone());
    if !canonical_path.starts_with(&canonical_dir) {
        return Err("Path traversal attempt detected".to_string());
    }

    // Evict from the load cache so the file can be deleted on Windows.
    evict_from_cache(&path);

    std::fs::remove_file(&path)
        .map_err(|e| format!("Failed to remove plugin '{filename}': {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_uninstall_filename_rejects_path_traversal() {
        let err = validate_uninstall_filename("../evil.dll").unwrap_err();
        assert!(err.contains("no path separators"));
    }

    #[test]
    fn validate_uninstall_filename_rejects_wrong_extension() {
        let err = validate_uninstall_filename("evil.txt").unwrap_err();
        assert!(err.contains("Unsupported extension"));
    }

    #[test]
    fn validate_uninstall_filename_accepts_platform_extension() {
        let candidate = if cfg!(target_os = "windows") {
            "safe.dll"
        } else if cfg!(target_os = "macos") {
            "safe.dylib"
        } else {
            "safe.so"
        };

        let safe = validate_uninstall_filename(candidate).unwrap();
        assert_eq!(safe, candidate);
    }
}

/// Open the user plugin directory in the native file manager.
#[command]
pub async fn open_plugin_directory(app: tauri::AppHandle) -> Result<(), String> {
    let dir = get_user_plugin_dir(&app)?;

    #[cfg(target_os = "windows")]
    std::process::Command::new("explorer")
        .arg(&dir)
        .spawn()
        .map_err(|e| format!("Failed to open Explorer: {e}"))?;

    #[cfg(target_os = "macos")]
    std::process::Command::new("open")
        .arg(&dir)
        .spawn()
        .map_err(|e| format!("Failed to open Finder: {e}"))?;

    #[cfg(target_os = "linux")]
    std::process::Command::new("xdg-open")
        .arg(&dir)
        .spawn()
        .map_err(|e| format!("Failed to open file manager: {e}"))?;

    Ok(())
}
