#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use maple_core::output::{cheat_table, offsets_header, plain_text};
use maple_core::{Arch, BuildStamp, Finding, Kind, MemorySource, diff, parse_dump, parse_stamp};
use rusqlite::Connection;

mod history;

struct AppState {
    cancel: Arc<AtomicBool>,
    last: Arc<Mutex<Option<LastScan>>>,
    db: Arc<Mutex<Connection>>,
}

struct LastScan {
    findings: Vec<Finding>,
    module_name: String,
    module_base: u64,
    stamp: BuildStamp,
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
    build_hash: String,
    build_version: Option<String>,
}

#[derive(Serialize)]
struct DiffRowView {
    name: String,
    category: String,
    state: String,
    old: Option<String>,
    new: Option<String>,
    old_bytes: Option<String>,
    new_bytes: Option<String>,
}

#[derive(Serialize)]
struct DiffView {
    unchanged: usize,
    moved: usize,
    added: usize,
    removed: usize,
    changed: Option<bool>,
    old_build: Option<String>,
    new_build: Option<String>,
    rows: Vec<DiffRowView>,
}

#[derive(Serialize)]
struct MatrixColumn {
    id: i64,
    label: String,
}

#[derive(Serialize)]
struct MatrixRow {
    name: String,
    category: String,
    cells: Vec<Option<String>>,
}

#[derive(Serialize)]
struct MatrixView {
    columns: Vec<MatrixColumn>,
    rows: Vec<MatrixRow>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn read_window<S: MemorySource>(source: &S, addr: usize, n: usize) -> Option<String> {
    let mut buf = vec![0u8; n];
    let read = source.read_into(addr, &mut buf).ok()?;
    if read == 0 {
        return None;
    }
    Some(buf[..read].iter().map(|b| format!("{b:02X}")).collect())
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
    if let Ok(mut conn) = db.lock() {
        let _ = history::insert_scan(&mut conn, &record, &new_findings);
    }

    *last.lock().unwrap() = Some(LastScan {
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
async fn attach_and_scan(
    state: tauri::State<'_, AppState>,
    req: ScanRequest,
) -> Result<ScanReport, String> {
    let cancel = state.cancel.clone();
    let last = state.last.clone();
    let db = state.db.clone();
    cancel.store(false, Ordering::SeqCst);
    match tauri::async_runtime::spawn_blocking(move || run_scan(&cancel, &last, &db, req)).await {
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

fn build_label(stamp: &BuildStamp) -> String {
    match &stamp.version {
        Some(v) => format!("{} (v{v})", stamp.short()),
        None => stamp.short(),
    }
}

fn build_diff_view(
    old: &[Finding],
    new: &[Finding],
    old_build: Option<String>,
    new_build: Option<String>,
    changed: Option<bool>,
) -> DiffView {
    let report = diff(old, new);
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
fn diff_dumps(old: String, new: String) -> DiffView {
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

#[tauri::command]
fn history_builds(state: tauri::State<'_, AppState>) -> Result<Vec<history::BuildGroup>, String> {
    let conn = state.db.lock().map_err(|e| e.to_string())?;
    history::group_by_build(&conn).map_err(|e| e.to_string())
}

#[tauri::command]
fn history_findings(
    state: tauri::State<'_, AppState>,
    id: i64,
) -> Result<Vec<history::FindingRow>, String> {
    let conn = state.db.lock().map_err(|e| e.to_string())?;
    history::findings(&conn, id).map_err(|e| e.to_string())
}

#[tauri::command]
fn history_diff(state: tauri::State<'_, AppState>, a: i64, b: i64) -> Result<DiffView, String> {
    let conn = state.db.lock().map_err(|e| e.to_string())?;
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
    for row in &mut view.rows {
        row.old_bytes = old_bytes.get(&row.name).cloned().flatten();
        row.new_bytes = new_bytes.get(&row.name).cloned().flatten();
    }
    Ok(view)
}

#[tauri::command]
fn history_delete(state: tauri::State<'_, AppState>, id: i64) -> Result<(), String> {
    let conn = state.db.lock().map_err(|e| e.to_string())?;
    history::delete_scan(&conn, id).map_err(|e| e.to_string())
}

#[tauri::command]
fn history_clear(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let conn = state.db.lock().map_err(|e| e.to_string())?;
    history::clear(&conn).map_err(|e| e.to_string())
}

#[tauri::command]
fn history_export(
    state: tauri::State<'_, AppState>,
    id: i64,
    format: String,
) -> Result<String, String> {
    let conn = state.db.lock().map_err(|e| e.to_string())?;
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
    Ok(match format.as_str() {
        "header" => offsets_header(&findings, &meta.module, base),
        "ce" => cheat_table(&findings, &meta.module),
        _ => plain_text(&findings, &meta.module, base, None),
    })
}

#[tauri::command]
fn history_matrix(state: tauri::State<'_, AppState>, ids: Vec<i64>) -> Result<MatrixView, String> {
    let conn = state.db.lock().map_err(|e| e.to_string())?;
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

#[tauri::command]
fn disassemble(hex: String, bits: u32, base: String) -> Vec<String> {
    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

    let clean: String = hex.chars().filter(char::is_ascii_hexdigit).collect();
    let bytes: Vec<u8> = (0..clean.len() / 2)
        .filter_map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok())
        .collect();
    if bytes.is_empty() {
        return Vec::new();
    }
    let bitness = if bits == 32 { 32 } else { 64 };
    let ip = u64::from_str_radix(base.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .unwrap_or(0);
    let mut decoder = Decoder::with_ip(bitness, &bytes, ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instr = Instruction::default();
    let mut out = Vec::new();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        let mut text = String::new();
        formatter.format(&instr, &mut text);
        out.push(format!("{:08X}  {text}", instr.ip()));
    }
    out
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
            db: Arc::new(Mutex::new(
                history::open(&history::default_db_path())
                    .unwrap_or_else(|_| history::open_memory()),
            )),
        })
        .invoke_handler(tauri::generate_handler![
            engine_version,
            parse_patterns_text,
            attach_and_scan,
            cancel_scan,
            export_text,
            diff_dumps,
            history_builds,
            history_findings,
            history_diff,
            history_delete,
            history_clear,
            history_export,
            history_matrix,
            disassemble,
            pick_open_file,
            pick_save_file,
            read_text_file,
            write_text_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running MapleDumper");
}
