#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use maple_core::output::{cheat_table, offsets_header, plain_text};
use maple_core::{Arch, Finding, Kind};

struct AppState {
    cancel: Arc<AtomicBool>,
    last: Arc<Mutex<Option<LastScan>>>,
}

struct LastScan {
    findings: Vec<Finding>,
    module_name: String,
    module_base: u64,
}

#[derive(Serialize)]
struct PatternView {
    name: String,
    kind: String,
    category: String,
    aob: String,
    note: String,
}

#[derive(Deserialize)]
struct ScanRequest {
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
struct RowView {
    name: String,
    category: String,
    kind: String,
    value: Option<String>,
    is_offset: bool,
    matches: usize,
    status: String,
    note: String,
    pattern: String,
}

#[derive(Serialize)]
struct ScanReport {
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
}

fn arch_of(s: &str) -> Arch {
    if s.eq_ignore_ascii_case("x86") || s.contains("32") {
        Arch::X86
    } else {
        Arch::X64
    }
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Direct => "direct",
        Kind::Pointer => "pointer",
        Kind::Call => "call",
        Kind::Offset => "offset",
        Kind::Header => "header",
    }
}

#[tauri::command]
fn engine_version() -> String {
    maple_core::VERSION.to_string()
}

#[tauri::command]
fn parse_patterns_text(text: String, arch: String) -> Vec<PatternView> {
    let a = arch_of(&arch);
    maple_core::pattern::parse_patterns(&text, a)
        .iter()
        .map(|p| {
            let (kind, base) = Kind::classify(&p.name);
            let category = p
                .category
                .clone()
                .unwrap_or_else(|| maple_core::categorizer::builtin_category(base).to_string());
            PatternView {
                name: p.name.clone(),
                kind: kind_label(kind).to_string(),
                category,
                aob: p.signature.to_aob(),
                note: p.note.clone().unwrap_or_default(),
            }
        })
        .collect()
}

#[cfg(windows)]
fn run_scan(
    cancel: &AtomicBool,
    last: &Mutex<Option<LastScan>>,
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

    let patterns = maple_core::pattern::parse_patterns(&req.patterns, arch);
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
    let result = maple_core::scan(&target, target.module.base, &regions, &patterns, arch);
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
                kind: kind_label(kind).to_string(),
                value: r.value.map(|v| format!("0x{v:X}")),
                is_offset: r.is_offset,
                matches: r.matches,
                status: r.status.label().to_string(),
                note: r.note.clone(),
                pattern: r.pattern.clone(),
            }
        })
        .collect();

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
    };

    *last.lock().unwrap() = Some(LastScan {
        findings: result.findings,
        module_name,
        module_base,
    });

    Ok(report)
}

#[cfg(not(windows))]
fn run_scan(
    _cancel: &AtomicBool,
    _last: &Mutex<Option<LastScan>>,
    _req: ScanRequest,
) -> Result<ScanReport, String> {
    Err("process scanning is only available on Windows".to_string())
}

#[tauri::command]
async fn attach_and_scan(
    state: tauri::State<'_, AppState>,
    req: ScanRequest,
) -> Result<ScanReport, String> {
    let cancel = state.cancel.clone();
    let last = state.last.clone();
    cancel.store(false, Ordering::SeqCst);
    match tauri::async_runtime::spawn_blocking(move || run_scan(&cancel, &last, req)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn cancel_scan(state: tauri::State<'_, AppState>) {
    state.cancel.store(true, Ordering::SeqCst);
}

#[tauri::command]
fn export_text(state: tauri::State<'_, AppState>, format: String) -> Result<String, String> {
    let guard = state.last.lock().unwrap();
    let last = guard
        .as_ref()
        .ok_or_else(|| "run a scan first; there is nothing to export yet".to_string())?;
    let out = match format.as_str() {
        "header" => offsets_header(&last.findings, &last.module_name, last.module_base),
        "ce" => cheat_table(&last.findings, &last.module_name),
        _ => plain_text(&last.findings, &last.module_name, last.module_base),
    };
    Ok(out)
}

#[tauri::command]
async fn pick_open_file() -> Option<String> {
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
async fn pick_save_file(default_name: String) -> Option<String> {
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
fn read_text_file(path: String) -> Result<String, String> {
    std::fs::read(&path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn write_text_file(path: String, contents: String) -> Result<(), String> {
    std::fs::write(&path, contents).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            cancel: Arc::new(AtomicBool::new(false)),
            last: Arc::new(Mutex::new(None)),
        })
        .invoke_handler(tauri::generate_handler![
            engine_version,
            parse_patterns_text,
            attach_and_scan,
            cancel_scan,
            export_text,
            pick_open_file,
            pick_save_file,
            read_text_file,
            write_text_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running MapleDumper");
}
