#[tauri::command]
pub fn open_file_picker() -> Result<Option<String>, String> {
    let selected = rfd::FileDialog::new().pick_file();
    Ok(selected.map(|p| p.to_string_lossy().to_string()))
}
