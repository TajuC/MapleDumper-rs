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
    confidence: u8,
    trace: Option<String>,
    /// The structured resolution trace, so the Inspector can show instruction/operand/target facts.
    trace_detail: Option<maple_core::ResolveTrace>,
    candidates: Vec<String>,
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
    regions_detail: Vec<RegionView>,
    build_hash: String,
    build_version: Option<String>,
    /// Non-fatal problems the user should see: a failed history save, for example, which used to be
    /// logged to stderr only and left the scan looking fully successful.
    warnings: Vec<String>,
}

#[derive(Serialize)]
pub struct RegionView {
    base: String,
    size: i64,
    findings: i64,
}

#[tauri::command]
pub fn engine_version() -> String {
    maple_core::VERSION.to_string()
}

/// A stable BLAKE3 of the pattern set, order-independent, so a saved scan records exactly which
/// patterns produced it. Each pattern contributes its name and its AOB (or string-anchor form).
#[cfg(windows)]
fn pattern_set_hash(patterns: &[maple_core::pattern::Pattern]) -> String {
    let mut parts: Vec<String> = patterns
        .iter()
        .map(|p| {
            let body = match &p.string_anchor {
                Some(a) => match &a.also {
                    Some(also) => format!("@string={} @also={also}", a.text),
                    None => format!("@string={}", a.text),
                },
                None => p.signature.to_aob(),
            };
            format!("{}\u{1}{body}", p.name)
        })
        .collect();
    parts.sort();
    history::content_hash(parts.join("\u{2}").as_bytes())
}

#[tauri::command]
pub fn parse_patterns_text(text: String, arch: String) -> Vec<PatternView> {
    // A display-only parse preview, not a scan, so an unparseable arch falls back rather than erroring.
    let a = arch_of(&arch).unwrap_or(maple_core::Arch::X64);
    maple_core::pattern::parse_patterns(&text, a)
        .iter()
        .map(|p| {
            let kind = Kind::classify(&p.name).0;
            let category = p.category.clone();
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

    let arch = arch_of(&req.arch)?;
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

    let (patterns, parse_warnings) =
        match maple_core::pattern::parse_patterns_strict(&req.patterns, arch) {
            Ok(parsed) => {
                // These were previously dropped on the floor; surface them so a weak or suffix-derived
                // pattern is visible to the user instead of silently accepted.
                let warns = parsed
                    .warnings
                    .iter()
                    .map(|w| format!("pattern line {}: {}", w.line, w.message))
                    .collect::<Vec<_>>();
                (parsed.patterns, warns)
            }
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
    // Fail clearly on a definite architecture mismatch instead of silently scanning the wrong
    // bitness and reporting everything "not found". One shared message, so the CLI and app agree.
    if let Some(msg) = maple_core::arch_mismatch(arch, target.module_arch(), req.module.trim()) {
        return Err(msg);
    }
    let module_base = target.module.base as u64;
    // The module's executable regions, enumerated once and reused: as the scan set when
    // `code_only`, as the `@section` validation set always, and for the build fingerprint below.
    let code_regions = target.code_regions();
    let regions = if req.code_only {
        code_regions.clone()
    } else {
        target.regions()
    };
    let bytes_scanned: u64 = regions.iter().map(|r| r.size as u64).sum();
    let region_count = regions.len();
    let scan_started = Instant::now();
    let result = maple_core::scan_live(
        &target,
        target.module.base,
        target.module.size,
        &regions,
        &code_regions,
        &patterns,
        arch,
    );
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
                confidence: r.confidence,
                trace: r.trace.clone(),
                trace_detail: r.trace_detail.clone(),
                candidates: r.candidates.iter().map(|v| format!("0x{v:X}")).collect(),
            }
        })
        .collect();

    let mut stamp = BuildStamp::capture(&target, target.module.base, &code_regions);
    stamp.version = target.file_version();

    let module_addr = target.module.base;
    let regions_detail: Vec<RegionView> = regions
        .iter()
        .map(|reg| {
            let end = reg.base + reg.size;
            let findings = result
                .rows
                .iter()
                .filter(|r| {
                    !r.is_offset
                        && r.value.is_some_and(|v| {
                            let abs = module_addr + v as usize;
                            abs >= reg.base && abs < end
                        })
                })
                .count();
            RegionView {
                base: format!("0x{:X}", reg.base),
                size: reg.size as i64,
                findings: findings as i64,
            }
        })
        .collect();

    let mut report = ScanReport {
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
        regions_detail,
        build_hash: stamp.short(),
        build_version: stamp.version.clone(),
        // Start with the parse-time advisories and the scan-time advisories (partial reads, @hits
        // expectation violations); a later history-save failure appends to the same channel.
        warnings: parse_warnings
            .into_iter()
            .chain(result.warnings.iter().cloned())
            .collect(),
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
                confidence: i64::from(r.confidence),
                trace: r.trace.clone(),
                candidates: (r.candidates.len() > 1).then(|| {
                    r.candidates
                        .iter()
                        .map(|v| format!("0x{v:X}"))
                        .collect::<Vec<_>>()
                        .join(",")
                }),
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
        module_size: target.module.size as i64,
        pattern_set_hash: pattern_set_hash(&patterns),
        scanner_version: maple_core::VERSION.to_string(),
    };
    {
        let mut conn = crate::state::lock_db(db);
        if let Err(e) = history::insert_scan(&mut conn, &record, &new_findings) {
            // Surface the failure to the user instead of only logging it: the scan still produced
            // results, but it was not persisted to history, and silently dropping that reads as a
            // clean save.
            eprintln!("[warn] failed to save scan to history: {e}");
            report
                .warnings
                .push(format!("scan completed but was not saved to history: {e}"));
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
