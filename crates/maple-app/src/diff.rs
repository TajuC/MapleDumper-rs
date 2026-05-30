//! Dump diffing: parse two text dumps and report what moved, was added, or
//! removed between them. The shared diff plumbing here is also reused by the
//! history command surface in [`crate::history_cmd`].

use std::collections::HashMap;

use serde::Serialize;

use maple_core::{BuildStamp, Finding, parse_dump, parse_stamp};

#[derive(Serialize)]
pub struct DiffRowView {
    name: String,
    category: String,
    state: String,
    old: Option<String>,
    new: Option<String>,
    old_bytes: Option<String>,
    new_bytes: Option<String>,
}

#[derive(Serialize)]
pub struct DiffView {
    unchanged: usize,
    moved: usize,
    added: usize,
    removed: usize,
    changed: Option<bool>,
    old_build: Option<String>,
    new_build: Option<String>,
    rows: Vec<DiffRowView>,
}

impl DiffView {
    /// Fill each row's raw byte windows from per-scan lookups keyed by finding
    /// name. The history diff has these bytes saved; the pasted-dump diff does
    /// not, so the columns simply stay empty there.
    pub(crate) fn attach_bytes(
        &mut self,
        old: &HashMap<String, Option<String>>,
        new: &HashMap<String, Option<String>>,
    ) {
        for row in &mut self.rows {
            row.old_bytes = old.get(&row.name).cloned().flatten();
            row.new_bytes = new.get(&row.name).cloned().flatten();
        }
    }
}

fn build_label(stamp: &BuildStamp) -> String {
    match &stamp.version {
        Some(v) => format!("{} (v{v})", stamp.short()),
        None => stamp.short(),
    }
}

pub(crate) fn build_diff_view(
    old: &[Finding],
    new: &[Finding],
    old_build: Option<String>,
    new_build: Option<String>,
    changed: Option<bool>,
) -> DiffView {
    let report = maple_core::diff(old, new);
    let mut rows = Vec::new();
    for m in &report.moved {
        rows.push(DiffRowView {
            name: m.name.clone(),
            category: m.category.clone(),
            state: "moved".to_string(),
            old: Some(format!("0x{:X}", m.old)),
            new: Some(format!("0x{:X}", m.new)),
            old_bytes: None,
            new_bytes: None,
        });
    }
    for f in &report.added {
        rows.push(DiffRowView {
            name: f.name.clone(),
            category: f.category.clone(),
            state: "new".to_string(),
            old: None,
            new: Some(format!("0x{:X}", f.value)),
            old_bytes: None,
            new_bytes: None,
        });
    }
    for f in &report.removed {
        rows.push(DiffRowView {
            name: f.name.clone(),
            category: f.category.clone(),
            state: "removed".to_string(),
            old: Some(format!("0x{:X}", f.value)),
            new: None,
            old_bytes: None,
            new_bytes: None,
        });
    }
    DiffView {
        unchanged: report.unchanged,
        moved: report.moved.len(),
        added: report.added.len(),
        removed: report.removed.len(),
        changed,
        old_build,
        new_build,
        rows,
    }
}

#[tauri::command]
pub fn diff_dumps(old: String, new: String) -> DiffView {
    let old_stamp = parse_stamp(&old);
    let new_stamp = parse_stamp(&new);
    let changed = match (&old_stamp, &new_stamp) {
        (Some(a), Some(b)) => Some(a.hash != b.hash),
        _ => None,
    };
    build_diff_view(
        &parse_dump(&old),
        &parse_dump(&new),
        old_stamp.as_ref().map(build_label),
        new_stamp.as_ref().map(build_label),
        changed,
    )
}
