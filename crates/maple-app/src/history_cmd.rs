//! The Tauri command surface over the scan-history store in [`crate::history`]:
//! browsing pages, per-scan findings, cross-build diffs, the comparison matrix,
//! and per-scan export. The SQLite access itself lives in `history.rs`; this
//! module only adapts it to the frontend's view types.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use maple_core::Finding;
use maple_core::output::export;

use crate::diff::{DiffView, build_diff_view};
use crate::history;
use crate::state::AppState;

#[derive(Serialize)]
pub struct HistoryPage {
    total: i64,
    scans: Vec<history::ScanRow>,
}

#[derive(Serialize)]
pub struct MatrixColumn {
    id: i64,
    label: String,
}

#[derive(Serialize)]
pub struct MatrixRow {
    name: String,
    category: String,
    cells: Vec<Option<String>>,
}

#[derive(Serialize)]
pub struct MatrixView {
    columns: Vec<MatrixColumn>,
    rows: Vec<MatrixRow>,
}

fn to_findings(rows: &[history::FindingRow]) -> Vec<Finding> {
    rows.iter()
        .filter_map(|r| {
            let raw = r.value.as_ref()?;
            let hex = raw.trim_start_matches("0x").trim_start_matches("0X");
            let value = u64::from_str_radix(hex, 16).ok()?;
            Some(Finding {
                name: r.name.clone(),
                category: r.category.clone(),
                value,
                is_offset: r.is_offset,
            })
        })
        .collect()
}

fn meta_label(meta: &history::ScanRow) -> String {
    match &meta.build_version {
        Some(v) => format!("{} (v{v})", meta.build_hash),
        None => meta.build_hash.clone(),
    }
}

#[tauri::command]
pub fn history_builds(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<history::BuildGroup>, String> {
    let conn = crate::state::lock_db(&state.db);
    history::group_by_build(&conn).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn history_page(
    state: tauri::State<'_, AppState>,
    limit: i64,
    offset: i64,
) -> Result<HistoryPage, String> {
    let conn = crate::state::lock_db(&state.db);
    let total = history::count_scans(&conn).map_err(|e| e.to_string())?;
    let scans = history::list_scans_page(&conn, limit.clamp(1, 500), offset.max(0))
        .map_err(|e| e.to_string())?;
    Ok(HistoryPage { total, scans })
}

#[tauri::command]
pub fn history_findings(
    state: tauri::State<'_, AppState>,
    id: i64,
) -> Result<Vec<history::FindingRow>, String> {
    let conn = crate::state::lock_db(&state.db);
    history::findings(&conn, id).map_err(|e| e.to_string())
}

/// The JSON-encoded read gaps for a saved scan (its partial-read coverage), or `None` if it read in
/// full. The History view shows a coverage note when this is present.
#[tauri::command]
pub fn history_read_gaps(
    state: tauri::State<'_, AppState>,
    id: i64,
) -> Result<Option<String>, String> {
    let conn = crate::state::lock_db(&state.db);
    history::scan_read_gaps(&conn, id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn history_diff(state: tauri::State<'_, AppState>, a: i64, b: i64) -> Result<DiffView, String> {
    let conn = crate::state::lock_db(&state.db);
    let old_rows = history::findings(&conn, a).map_err(|e| e.to_string())?;
    let new_rows = history::findings(&conn, b).map_err(|e| e.to_string())?;
    let old_meta = history::scan_row(&conn, a).map_err(|e| e.to_string())?;
    let new_meta = history::scan_row(&conn, b).map_err(|e| e.to_string())?;
    let changed = match (&old_meta, &new_meta) {
        (Some(x), Some(y)) => Some(x.build_hash != y.build_hash),
        _ => None,
    };
    let mut view = build_diff_view(
        &to_findings(&old_rows),
        &to_findings(&new_rows),
        old_meta.map(|m| meta_label(&m)),
        new_meta.map(|m| meta_label(&m)),
        changed,
    );
    let old_bytes: HashMap<String, Option<String>> =
        old_rows.into_iter().map(|r| (r.name, r.bytes)).collect();
    let new_bytes: HashMap<String, Option<String>> =
        new_rows.into_iter().map(|r| (r.name, r.bytes)).collect();
    view.attach_bytes(&old_bytes, &new_bytes);
    Ok(view)
}

#[tauri::command]
pub fn history_delete(state: tauri::State<'_, AppState>, id: i64) -> Result<(), String> {
    let conn = crate::state::lock_db(&state.db);
    history::delete_scan(&conn, id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn history_clear(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let conn = crate::state::lock_db(&state.db);
    history::clear(&conn).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn history_export(
    state: tauri::State<'_, AppState>,
    id: i64,
    format: String,
) -> Result<String, String> {
    let conn = crate::state::lock_db(&state.db);
    let meta = history::scan_row(&conn, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "scan not found".to_string())?;
    let findings = to_findings(&history::findings(&conn, id).map_err(|e| e.to_string())?);
    let base = u64::from_str_radix(
        meta.module_base
            .trim_start_matches("0x")
            .trim_start_matches("0X"),
        16,
    )
    .unwrap_or(0);
    Ok(export(&findings, &meta.module, base, None, &format))
}

#[tauri::command]
pub fn history_matrix(
    state: tauri::State<'_, AppState>,
    ids: Vec<i64>,
) -> Result<MatrixView, String> {
    let conn = crate::state::lock_db(&state.db);
    let mut columns = Vec::new();
    let mut per_scan: Vec<HashMap<String, Option<String>>> = Vec::new();
    let mut categories: BTreeMap<String, String> = BTreeMap::new();
    for &id in &ids {
        let label = history::scan_row(&conn, id)
            .map_err(|e| e.to_string())?
            .map_or_else(|| id.to_string(), |m| meta_label(&m));
        columns.push(MatrixColumn { id, label });
        let mut values = HashMap::new();
        for f in history::findings(&conn, id).map_err(|e| e.to_string())? {
            categories.entry(f.name.clone()).or_insert(f.category);
            values.insert(f.name, f.value);
        }
        per_scan.push(values);
    }
    let mut rows: Vec<MatrixRow> = categories
        .into_iter()
        .map(|(name, category)| {
            let cells = per_scan
                .iter()
                .map(|m| m.get(&name).cloned().flatten())
                .collect();
            MatrixRow {
                name,
                category,
                cells,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.category.cmp(&b.category).then(a.name.cmp(&b.name)));
    Ok(MatrixView { columns, rows })
}
