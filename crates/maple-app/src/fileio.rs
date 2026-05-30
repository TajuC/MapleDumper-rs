//! File-picker dialogs and the guarded text file read/write commands.
//!
//! The frontend only reads and writes pattern lists and exported reports, so the
//! read/write commands are confined to text-like extensions instead of letting
//! an injected script touch arbitrary files on disk.

#[tauri::command]
pub async fn pick_open_file() -> Option<String> {
    tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .add_filter("Pattern lists", &["json", "txt", "ini", "cfg"])
            .add_filter("All files", &["*"])
            .pick_file()
            .map(|p| p.to_string_lossy().into_owned())
    })
    .await
    .ok()
    .flatten()
}

#[tauri::command]
pub async fn pick_save_file(default_name: String) -> Option<String> {
    tauri::async_runtime::spawn_blocking(move || {
        rfd::FileDialog::new()
            .set_file_name(default_name)
            .save_file()
            .map(|p| p.to_string_lossy().into_owned())
    })
    .await
    .ok()
    .flatten()
}

#[tauri::command]
pub async fn pick_open_files() -> Vec<String> {
    tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .add_filter("Executables", &["exe", "dll", "bin"])
            .add_filter("All files", &["*"])
            .pick_files()
            .map(|v| {
                v.into_iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

fn is_text_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".txt", ".h", ".hpp", ".inc", ".json", ".ct", ".csv", ".md", ".ini", ".cfg", ".log",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
}

#[tauri::command]
pub fn read_text_file(path: String) -> Result<String, String> {
    if !is_text_path(&path) {
        return Err("only text, pattern, and report files can be read".to_string());
    }
    std::fs::read(&path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn write_text_file(path: String, contents: String) -> Result<(), String> {
    if !is_text_path(&path) {
        return Err("only text, pattern, and report files can be written".to_string());
    }
    std::fs::write(&path, contents).map_err(|e| e.to_string())
}
