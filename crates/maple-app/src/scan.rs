//! The process-scan feature: parse a pattern list, attach to the target, scan
//! its memory, persist the run to history, and cache it for export.

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use maple_core::{Arch, BuildStamp, Kind};

use crate::history;
use crate::jobs::JobId;
use crate::state::{AppState, LastScan};
use crate::util::{arch_of, kind_label, now_unix, read_window};

#[derive(Serialize)]
pub struct PatternView {
    name: String,
    r#type: String,
    category: String,
    aob: String,
    note: String,
}

#[derive(Deserialize)]
pub struct ScanRequest {
    locator: String,
    target: String,
    module: String,
    arch: String,
    wait: bool,
    timeout_secs: Option<u64>,
    code_only: bool,
    patterns: String,
}

#[derive(Serialize)]
pub struct RowView {
    name: String,
    category: String,
    r#type: String,
    value: Option<String>,
    is_offset: bool,
    matches: usize,
    status: String,
    note: String,
    pattern: String,
}

#[derive(Serialize)]
pub struct ScanReport {
    module_name: String,
    module_base: String,
    rows: Vec<RowView>,
    found: usize,
    unresolved: usize,
    not_found: usize,
    total_matches: usize,
    elapsed_ms: u128,
    attach_ms: u128,
    scan_ms: u128,
    bytes_scanned: u64,
    regions: usize,
    build_hash: String,
    build_version: Option<String>,
}

#[tauri::command]
pub fn engine_version() -> String {
    maple_core::VERSION.to_string()
}

#[tauri::command]
pub fn parse_patterns_text(text: String, arch: String) -> Vec<PatternView> {
    let a = arch_of(&arch);
    maple_core::pattern::parse_patterns(&text, a)
        .iter()
        .map(|p| {
            let (kind, base) = Kind::classify(&p.name);
            let category = p
                .category
                .clone()
                .unwrap_or_else(|| maple_core::categorizer::builtin_category(base).to_string());
            let (r#type, aob) = match &p.string_anchor {
                Some(anchor) => {
                    let aob = match &anchor.also {
                        Some(also) => format!("@string={} @also={also}", anchor.text),
                        None => format!("@string={}", anchor.text),
                    };
                    ("string".to_string(), aob)
                }
                None => (kind_label(kind).to_string(), p.signature.to_aob()),
            };
            PatternView {
                name: p.name.clone(),
                r#type,
                category,
                aob,
                note: p.note.clone().unwrap_or_default(),
            }
        })
        .collect()
}

#[cfg(windows)]
fn run_scan(
    cancel: &AtomicBool,
    last: &Mutex<Option<LastScan>>,
    db: &Mutex<Connection>,
    req: ScanRequest,
) -> Result<ScanReport, String> {
    use maple_core::{AttachOptions, Locator, Target};

    let arch = arch_of(&req.arch);
    let locator = if req.locator.eq_ignore_ascii_case("class") {
        Locator::Class(req.target.clone())
    } else {
        Locator::Name(req.target.clone())
    };
    let opts = AttachOptions {
        wait: req.wait,
        timeout: req.timeout_secs.map(Duration::from_secs),
        poll: Duration::from_millis(300),
    };

    let patterns = match maple_core::pattern::parse_patterns_strict(&req.patterns, arch) {
        Ok(parsed) => parsed.patterns,
        Err(issues) => {
            let detail = issues
                .iter()
                .filter(|i| i.severity == maple_core::pattern::ParseSeverity::Error)
                .map(|i| format!("line {}: {}", i.line, i.message))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!("pattern errors: {detail}"));
        }
    };
    if patterns.is_empty() {
        return Err("no patterns to scan; the pattern list is empty".to_string());
    }

    let started = Instant::now();
    let target = Target::attach(&locator, &req.module, &opts, cancel).map_err(|e| e.to_string())?;
    let attach_ms = started.elapsed().as_millis();
    let module_base = target.module.base as u64;
    let regions = if req.code_only {
        target.code_regions()
    } else {
        target.regions()
    };
    let bytes_scanned: u64 = regions.iter().map(|r| r.size as u64).sum();
    let region_count = regions.len();
    let scan_started = Instant::now();
    let mut result = maple_core::scan(
        &target,
        target.module.base,
        target.module.size,
        &regions,
        &patterns,
        arch,
    );
    if patterns.iter().any(|p| p.string_anchor.is_some()) {
        let img = maple_core::ImageInput {
            label: String::new(),
            source: &target,
            base: target.module.base,
            size: target.module.size,
            code_regions: target.code_regions(),
            regions: target.regions(),
            import: None,
            arch,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        };
        maple_core::apply_string_anchors(&mut result, &img, &patterns);
    }
    let scan_ms = scan_started.elapsed().as_millis();
    let elapsed_ms = started.elapsed().as_millis();

    let module_name = {
        let m = req.module.trim();
        if m.is_empty() {
            req.target.trim().to_string()
        } else {
            m.to_string()
        }
    };

    let rows = result
        .rows
        .iter()
        .zip(patterns.iter())
        .map(|(r, p)| {
            let (kind, _) = Kind::classify(&p.name);
            RowView {
                name: r.name.clone(),
                category: r.category.clone(),
                r#type: kind_label(kind).to_string(),
                value: r.value.map(|v| format!("0x{v:X}")),
                is_offset: r.is_offset,
                matches: r.matches,
                status: r.status.label().to_string(),
                note: r.note.clone(),
                pattern: r.pattern.clone(),
            }
        })
        .collect();

    let mut stamp = BuildStamp::capture(&target, target.module.base, &target.code_regions());
    stamp.version = target.file_version();

    let report = ScanReport {
        module_name: module_name.clone(),
        module_base: format!("0x{module_base:X}"),
        rows,
        found: result.found.len(),
        unresolved: result.matched_unresolved.len(),
        not_found: result.not_found.len(),
        total_matches: result.total_matches,
        elapsed_ms,
        attach_ms,
        scan_ms,
        bytes_scanned,
        regions: region_count,
        build_hash: stamp.short(),
        build_version: stamp.version.clone(),
    };

    let new_findings: Vec<history::NewFinding> = result
        .rows
        .iter()
        .map(|r| {
            let bytes = if r.is_offset {
                None
            } else {
                r.value
                    .and_then(|v| read_window(&target, target.module.base + v as usize, 24))
            };
            history::NewFinding {
                name: r.name.clone(),
                category: r.category.clone(),
                value: r.value.map(|v| format!("0x{v:X}")),
                is_offset: r.is_offset,
                status: r.status.label().to_string(),
                matches: r.matches as i64,
                note: r.note.clone(),
                bytes,
            }
        })
        .collect();
    let record = history::NewScan {
        created_at: now_unix(),
        module: module_name.clone(),
        module_base: format!("0x{module_base:X}"),
        arch: if matches!(arch, Arch::X64) {
            "x64"
        } else {
            "x86"
        }
        .to_string(),
        build_hash: stamp.short(),
        build_version: stamp.version.clone(),
        build_timestamp: i64::from(stamp.timestamp),
        bytes: bytes_scanned as i64,
        regions: region_count as i64,
        found: result.found.len() as i64,
        unresolved: result.matched_unresolved.len() as i64,
        not_found: result.not_found.len() as i64,
        total_matches: result.total_matches as i64,
        scan_ms: scan_ms as i64,
    };
    {
        let mut conn = db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = history::insert_scan(&mut conn, &record, &new_findings) {
            eprintln!("[warn] failed to save scan to history: {e}");
        }
    }

    let mut guard = last
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = Some(LastScan {
        findings: result.findings,
        module_name,
        module_base,
        stamp,
    });

    Ok(report)
}

#[cfg(not(windows))]
fn run_scan(
    _cancel: &AtomicBool,
    _last: &Mutex<Option<LastScan>>,
    _db: &Mutex<Connection>,
    _req: ScanRequest,
) -> Result<ScanReport, String> {
    Err("process scanning is only available on Windows".to_string())
}

#[tauri::command]
pub async fn attach_and_scan(
    state: tauri::State<'_, AppState>,
    req: ScanRequest,
) -> Result<ScanReport, String> {
    let (id, token) = state.jobs.start();
    let last = state.last.clone();
    let db = state.db.clone();
    let result =
        tauri::async_runtime::spawn_blocking(move || run_scan(token.flag(), &last, &db, req)).await;
    state.jobs.finish(id);
    match result {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
pub fn cancel_scan(state: tauri::State<'_, AppState>) {
    state.jobs.cancel_all();
}

#[tauri::command]
pub fn cancel_job(state: tauri::State<'_, AppState>, job_id: JobId) {
    state.jobs.cancel(job_id);
}
