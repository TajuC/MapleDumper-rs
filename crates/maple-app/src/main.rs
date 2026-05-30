#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use maple_core::output::{cheat_table, offsets_header, plain_text};
use maple_core::{Arch, BuildStamp, Finding, Kind, MemorySource, diff, parse_dump, parse_stamp};
use maple_core::{
    FileImage, ImageInput, SigCandidate, SigOptions, SigReport, SigStage, TargetKind, TargetSpec,
    generate_cross_with_progress, generate_with_progress, try_signature_from_aob,
};
use rusqlite::Connection;
use tauri::Emitter;

mod history;
mod jobs;

use jobs::JobManager;

struct AppState {
    jobs: JobManager,
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
    r#type: String,
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
    r#type: String,
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

#[derive(Deserialize)]
struct AsmScanRequest {
    locator: String,
    target: String,
    module: String,
    arch: String,
    wait: bool,
    timeout_secs: Option<u64>,
    code_only: bool,
    from: Option<String>,
    to: Option<String>,
    lines: String,
}

#[derive(Serialize)]
struct AsmHitView {
    rva: String,
    address: String,
    bytes: String,
    lines: Vec<String>,
}

#[derive(Serialize)]
struct AsmScanReport {
    module_name: String,
    module_base: String,
    hits: Vec<AsmHitView>,
    total: usize,
    truncated: bool,
    elapsed_ms: u128,
    attach_ms: u128,
    scan_ms: u128,
    bytes_scanned: u64,
    regions: usize,
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

fn parse_addr(field: &Option<String>) -> Result<Option<usize>, String> {
    match field.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(raw) => {
            let hex = raw.trim_start_matches("0x").trim_start_matches("0X");
            usize::from_str_radix(hex, 16)
                .map(Some)
                .map_err(|_| format!("invalid address: {raw}"))
        }
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
async fn attach_and_scan(
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

#[cfg(windows)]
fn run_asm_scan(cancel: &AtomicBool, req: AsmScanRequest) -> Result<AsmScanReport, String> {
    use maple_core::{AttachOptions, Locator, Target};

    let arch = arch_of(&req.arch);
    let patterns = maple_core::parse_asm_patterns(&req.lines)
        .ok_or_else(|| "enter at least one assembly line to scan for".to_string())?;
    let from = parse_addr(&req.from)?;
    let to = parse_addr(&req.to)?;

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

    let started = Instant::now();
    let target = Target::attach(&locator, &req.module, &opts, cancel).map_err(|e| e.to_string())?;
    let attach_ms = started.elapsed().as_millis();
    let module_base = target.module.base as u64;

    let base_regions = if req.code_only {
        target.code_regions()
    } else {
        target.regions()
    };
    let regions = maple_core::memory::clip_regions(&base_regions, from, to);
    let bytes_scanned: u64 = regions.iter().map(|r| r.size as u64).sum();
    let region_count = regions.len();

    let scan_started = Instant::now();
    let hits = maple_core::assembly_scan(
        &target,
        target.module.base,
        &regions,
        arch,
        &patterns,
        cancel,
    );
    let scan_ms = scan_started.elapsed().as_millis();
    let elapsed_ms = started.elapsed().as_millis();

    if cancel.load(Ordering::SeqCst) {
        return Err("scan cancelled".to_string());
    }

    let module_name = {
        let m = req.module.trim();
        if m.is_empty() {
            req.target.trim().to_string()
        } else {
            m.to_string()
        }
    };

    const CAP: usize = 5000;
    let total = hits.len();
    let truncated = total > CAP;
    let view_hits = hits
        .into_iter()
        .take(CAP)
        .map(|h| AsmHitView {
            rva: format!("0x{:X}", h.rva),
            address: format!("0x{:X}", h.address),
            bytes: h
                .bytes
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" "),
            lines: h.lines,
        })
        .collect();

    Ok(AsmScanReport {
        module_name,
        module_base: format!("0x{module_base:X}"),
        hits: view_hits,
        total,
        truncated,
        elapsed_ms,
        attach_ms,
        scan_ms,
        bytes_scanned,
        regions: region_count,
    })
}

#[cfg(not(windows))]
fn run_asm_scan(_cancel: &AtomicBool, _req: AsmScanRequest) -> Result<AsmScanReport, String> {
    Err("assembly scanning is only available on Windows".to_string())
}

#[tauri::command]
async fn assembly_scan(
    state: tauri::State<'_, AppState>,
    req: AsmScanRequest,
) -> Result<AsmScanReport, String> {
    let (id, token) = state.jobs.start();
    let result =
        tauri::async_runtime::spawn_blocking(move || run_asm_scan(token.flag(), req)).await;
    state.jobs.finish(id);
    match result {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn cancel_scan(state: tauri::State<'_, AppState>) {
    state.jobs.cancel_all();
}

#[tauri::command]
fn cancel_job(state: tauri::State<'_, AppState>, job_id: jobs::JobId) {
    state.jobs.cancel(job_id);
}

#[tauri::command]
fn export_text(state: tauri::State<'_, AppState>, format: String) -> Result<String, String> {
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

#[derive(Serialize)]
struct HistoryPage {
    total: i64,
    scans: Vec<history::ScanRow>,
}

#[tauri::command]
fn history_page(
    state: tauri::State<'_, AppState>,
    limit: i64,
    offset: i64,
) -> Result<HistoryPage, String> {
    let conn = state.db.lock().map_err(|e| e.to_string())?;
    let total = history::count_scans(&conn).map_err(|e| e.to_string())?;
    let scans = history::list_scans_page(&conn, limit.clamp(1, 500), offset.max(0))
        .map_err(|e| e.to_string())?;
    Ok(HistoryPage { total, scans })
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
        let start_pos = decoder.position();
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            if decoder.set_position(start_pos + 1).is_err() {
                break;
            }
            decoder.set_ip(ip + (start_pos + 1) as u64);
            continue;
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

// The frontend only reads and writes pattern lists and exported reports, so confine these commands
// to text-like extensions instead of letting an injected script touch arbitrary files.
fn is_text_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".txt", ".h", ".hpp", ".inc", ".json", ".ct", ".csv", ".md", ".ini", ".cfg", ".log",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
}

#[tauri::command]
fn read_text_file(path: String) -> Result<String, String> {
    if !is_text_path(&path) {
        return Err("only text, pattern, and report files can be read".to_string());
    }
    std::fs::read(&path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn write_text_file(path: String, contents: String) -> Result<(), String> {
    if !is_text_path(&path) {
        return Err("only text, pattern, and report files can be written".to_string());
    }
    std::fs::write(&path, contents).map_err(|e| e.to_string())
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum SigJob {
    Aob {
        sig: String,
    },
    Ref {
        ref_path: String,
        rva: String,
    },
    Cross {
        sig: String,
        ref_path: String,
        rva: String,
    },
}

#[derive(Deserialize)]
struct SigGenRequest {
    clients: Vec<String>,
    jobs: Vec<SigJob>,
}

#[derive(Serialize)]
struct PeInfoView {
    name: String,
    arch: String,
    packed: bool,
    reasons: Vec<String>,
    max_entropy: f64,
}

#[derive(Serialize)]
struct PerVerView {
    label: String,
    match_rva: Option<String>,
    resolved_target_rva: Option<String>,
    target_type: Option<String>,
}

#[derive(Serialize)]
struct SigCandView {
    aob: String,
    suffix: String,
    grade: String,
    bytes: usize,
    fixed: usize,
    wildcards: usize,
    fixed_ratio: f64,
    reloc_safe: bool,
    per_version: Vec<PerVerView>,
    diags: Vec<String>,
}

#[derive(Serialize)]
struct SigInputView {
    label: String,
    packed: bool,
    reasons: Vec<String>,
}

#[derive(Serialize)]
struct SigHoldoutView {
    held_out: String,
    generated: bool,
    matched: bool,
}

#[derive(Serialize)]
struct SigReportView {
    arch: String,
    unique_builds: usize,
    inputs: Vec<SigInputView>,
    duplicate_groups: Vec<(String, Vec<String>)>,
    chosen: Option<SigCandView>,
    alternates: Vec<SigCandView>,
    rejected: Vec<SigCandView>,
    diagnostics: Vec<String>,
    holdout: Vec<SigHoldoutView>,
}

#[derive(Serialize)]
struct CrossView {
    expected_rva: String,
    matched_rva: Option<String>,
    agrees: bool,
}

#[derive(Serialize)]
struct SigJobResultView {
    label: String,
    report: Option<SigReportView>,
    cross: Option<CrossView>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SigGenResponse {
    jobs: Vec<SigJobResultView>,
}

fn sig_kind_str(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Code => "code",
        TargetKind::Data => "data",
        TargetKind::Import => "import",
        TargetKind::Unknown => "unknown",
    }
}

fn sig_cand_view(c: &SigCandidate) -> SigCandView {
    SigCandView {
        aob: c.aob.clone(),
        suffix: c.suffix.as_str().to_string(),
        grade: c.grade.letter().to_string(),
        bytes: c.bytes_len,
        fixed: c.fixed,
        wildcards: c.wildcards,
        fixed_ratio: c.fixed_ratio,
        reloc_safe: c.reloc_safe,
        per_version: c
            .per_version
            .iter()
            .map(|p| PerVerView {
                label: p.label.clone(),
                match_rva: p.match_rva.map(|v| format!("0x{v:X}")),
                resolved_target_rva: p.resolved_target_rva.map(|v| format!("0x{v:X}")),
                target_type: p.target_kind.map(|k| sig_kind_str(k).to_string()),
            })
            .collect(),
        diags: c.diags.iter().map(|d| d.to_string()).collect(),
    }
}

fn sig_report_view(r: &SigReport) -> SigReportView {
    SigReportView {
        arch: if matches!(r.arch, Arch::X64) {
            "x64"
        } else {
            "x86"
        }
        .to_string(),
        unique_builds: r.unique_builds,
        inputs: r
            .inputs
            .iter()
            .map(|i| SigInputView {
                label: i.label.clone(),
                packed: i.packed,
                reasons: i.reasons.clone(),
            })
            .collect(),
        duplicate_groups: r
            .duplicate_groups
            .iter()
            .map(|g| (format!("{:016X}", g.code_hash), g.labels.clone()))
            .collect(),
        chosen: r.chosen.as_ref().map(sig_cand_view),
        alternates: r.alternates.iter().map(sig_cand_view).collect(),
        rejected: r.rejected.iter().map(sig_cand_view).collect(),
        diagnostics: r.diagnostics.iter().map(|d| d.to_string()).collect(),
        holdout: Vec::new(),
    }
}

fn holdout_views(
    inputs: &[ImageInput],
    spec: &TargetSpec,
    opts: &SigOptions,
) -> Vec<SigHoldoutView> {
    maple_core::holdout_validate(inputs, spec, opts)
        .into_iter()
        .map(|h| SigHoldoutView {
            held_out: h.held_out,
            generated: h.generated,
            matched: h.matched_holdout,
        })
        .collect()
}

fn sig_report_view_with_holdout(
    r: &SigReport,
    inputs: &[ImageInput],
    spec: &TargetSpec,
    opts: &SigOptions,
) -> SigReportView {
    let mut view = sig_report_view(r);
    view.holdout = holdout_views(inputs, spec, opts);
    view
}

#[tauri::command]
fn inspect_pe(path: String) -> Result<PeInfoView, String> {
    let img = FileImage::open(std::path::Path::new(&path)).map_err(|e| e.to_string())?;
    let report = img.pack_report();
    let name = std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.clone());
    Ok(PeInfoView {
        name,
        arch: if matches!(img.arch(), Arch::X64) {
            "x64"
        } else {
            "x86"
        }
        .to_string(),
        packed: report.likely_packed,
        reasons: report.reasons,
        max_entropy: report.max_code_entropy,
    })
}

#[tauri::command]
async fn pick_open_files() -> Vec<String> {
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

#[derive(Clone, serde::Serialize)]
struct SigProgress {
    phase: &'static str,
    label: String,
    index: u32,
    total: u32,
    job: u32,
    jobs: u32,
}

fn stage_phase(stage: SigStage) -> (&'static str, u32, u32) {
    match stage {
        SigStage::Deduplicating => ("dedup", 0, 0),
        SigStage::ReadingCode { build, total } => ("read", build as u32, total as u32),
        SigStage::LocatingTarget => ("locate", 0, 0),
        SigStage::ScanningDirect => ("direct", 0, 0),
        SigStage::ScanningCallJmp => ("branch", 0, 0),
        SigStage::ScanningPtr => ("ptr", 0, 0),
        SigStage::Scoring => ("score", 0, 0),
    }
}

fn run_generate_signature(
    app: &tauri::AppHandle,
    req: SigGenRequest,
) -> Result<SigGenResponse, String> {
    if req.clients.is_empty() {
        return Err("add at least one client binary".to_string());
    }
    if req.jobs.is_empty() {
        return Err("add at least one target".to_string());
    }
    let label_of = |p: &str| {
        std::path::Path::new(p)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.to_string())
    };
    let jobs_total = req.jobs.len() as u32;
    let emit = |phase: &'static str, label: String, index: u32, total: u32, job: u32| {
        let _ = app.emit(
            "sig-progress",
            SigProgress {
                phase,
                label,
                index,
                total,
                job,
                jobs: jobs_total,
            },
        );
    };

    // Open and inspect every client once, then reuse the images across all jobs.
    let total = req.clients.len() as u32;
    let mut images: Vec<FileImage> = Vec::with_capacity(req.clients.len());
    for (k, p) in req.clients.iter().enumerate() {
        emit("load", label_of(p), k as u32 + 1, total, 0);
        images
            .push(FileImage::open(std::path::Path::new(p)).map_err(|e| format!("open {p}: {e}"))?);
    }
    emit("pack", String::new(), 0, 0, 0);
    let reports: Vec<_> = images.iter().map(FileImage::pack_report).collect();

    let mut inputs = Vec::with_capacity(images.len());
    for (k, img) in images.iter().enumerate() {
        inputs.push(ImageInput {
            label: label_of(&req.clients[k]),
            source: img,
            base: img.base(),
            size: img.size(),
            code_regions: img.code_regions(),
            regions: img.regions(),
            import: img.import_range(),
            arch: img.arch(),
            code_hash: img.code_hash(),
            packed: reports[k].likely_packed,
            pack_reasons: reports[k].reasons.clone(),
            reloc: Some(img),
        });
    }

    let ref_index = |ref_path: &str| -> Result<usize, String> {
        req.clients
            .iter()
            .position(|c| c == ref_path)
            .ok_or_else(|| "the reference must be one of the chosen clients".to_string())
    };
    let parse_rva = |raw: &str| -> Result<u64, String> {
        let hex = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid RVA '{raw}'"))
    };

    let opts = SigOptions::default();
    let mut results: Vec<SigJobResultView> = Vec::with_capacity(req.jobs.len());
    for (ji, job) in req.jobs.iter().enumerate() {
        let job_n = ji as u32 + 1;
        let mut on_stage = |stage: SigStage| {
            let (phase, index, total) = stage_phase(stage);
            emit(phase, String::new(), index, total, job_n);
        };
        let result = match job {
            SigJob::Aob { sig } => {
                let sig = sig.trim().to_string();
                match try_signature_from_aob(&sig) {
                    Err(e) => job_error(sig.clone(), format!("invalid signature: {e}")),
                    Ok(_) => {
                        let spec = TargetSpec::Aob(sig.clone());
                        let report = generate_with_progress(&inputs, &spec, &opts, &mut on_stage);
                        SigJobResultView {
                            label: sig,
                            report: Some(sig_report_view_with_holdout(
                                &report, &inputs, &spec, &opts,
                            )),
                            cross: None,
                            error: None,
                        }
                    }
                }
            }
            SigJob::Ref { ref_path, rva } => match (ref_index(ref_path), parse_rva(rva)) {
                (Ok(idx), Ok(rva_val)) => {
                    let spec = TargetSpec::Ref {
                        image: idx,
                        rva: rva_val,
                    };
                    let report = generate_with_progress(&inputs, &spec, &opts, &mut on_stage);
                    SigJobResultView {
                        label: format!("0x{rva_val:X}"),
                        report: Some(sig_report_view_with_holdout(&report, &inputs, &spec, &opts)),
                        cross: None,
                        error: None,
                    }
                }
                (Err(e), _) | (_, Err(e)) => job_error(rva.clone(), e),
            },
            SigJob::Cross { sig, ref_path, rva } => {
                let sig = sig.trim().to_string();
                let aob_ok = try_signature_from_aob(&sig)
                    .map(|_| ())
                    .map_err(|e| format!("invalid signature: {e}"));
                match (aob_ok, ref_index(ref_path), parse_rva(rva)) {
                    (Ok(()), Ok(idx), Ok(rva_val)) => {
                        let cr = generate_cross_with_progress(
                            &inputs,
                            &sig,
                            idx,
                            rva_val,
                            &opts,
                            &mut on_stage,
                        );
                        SigJobResultView {
                            label: format!("0x{rva_val:X}"),
                            report: Some(sig_report_view_with_holdout(
                                &cr.report,
                                &inputs,
                                &TargetSpec::Aob(sig.clone()),
                                &opts,
                            )),
                            cross: Some(CrossView {
                                expected_rva: format!("0x{:X}", cr.expected_rva),
                                matched_rva: cr.matched_rva.map(|v| format!("0x{v:X}")),
                                agrees: cr.agrees,
                            }),
                            error: None,
                        }
                    }
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => job_error(rva.clone(), e),
                }
            }
        };
        results.push(result);
    }
    Ok(SigGenResponse { jobs: results })
}

fn job_error(label: String, error: String) -> SigJobResultView {
    SigJobResultView {
        label,
        report: None,
        cross: None,
        error: Some(error),
    }
}

#[tauri::command]
async fn generate_signature(
    app: tauri::AppHandle,
    req: SigGenRequest,
) -> Result<SigGenResponse, String> {
    match tauri::async_runtime::spawn_blocking(move || run_generate_signature(&app, req)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

fn open_history_db() -> Connection {
    let path = history::default_db_path();
    match history::open(&path) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!(
                "[warn] could not open history database at {}: {e}; history will not be saved this session",
                path.display()
            );
            history::open_memory()
        }
    }
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            jobs: JobManager::default(),
            last: Arc::new(Mutex::new(None)),
            db: Arc::new(Mutex::new(open_history_db())),
        })
        .invoke_handler(tauri::generate_handler![
            engine_version,
            parse_patterns_text,
            attach_and_scan,
            assembly_scan,
            cancel_scan,
            cancel_job,
            export_text,
            diff_dumps,
            history_builds,
            history_page,
            history_findings,
            history_diff,
            history_delete,
            history_clear,
            history_export,
            history_matrix,
            disassemble,
            inspect_pe,
            pick_open_files,
            generate_signature,
            pick_open_file,
            pick_save_file,
            read_text_file,
            write_text_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running MapleDumper");
}
