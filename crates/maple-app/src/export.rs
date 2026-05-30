//! The `export_text` command: render the most recent scan as a C/C++ header, a
//! Cheat Engine table, or a plain-text dump.

use maple_core::output::{cheat_table, offsets_header, plain_text};

use crate::state::AppState;

#[tauri::command]
pub fn export_text(state: tauri::State<'_, AppState>, format: String) -> Result<String, String> {
    let guard = state
        .last
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let last = guard
        .as_ref()
        .ok_or_else(|| "run a scan first; there is nothing to export yet".to_string())?;
    let out = match format.as_str() {
        "header" => offsets_header(&last.findings, &last.module_name, last.module_base),
        "ce" => cheat_table(&last.findings, &last.module_name),
        _ => {
            let header = last.stamp.header_line();
            plain_text(
                &last.findings,
                &last.module_name,
                last.module_base,
                Some(&header),
            )
        }
    };
    Ok(out)
}
