//! The assembly-scan feature: assemble query lines, attach to the target, and
//! search its code for matching instruction sequences.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::state::AppState;
use crate::util::{arch_of, parse_addr};

#[derive(Deserialize)]
pub struct AsmScanRequest {
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
pub struct AsmHitView {
    rva: String,
    address: String,
    bytes: String,
    lines: Vec<String>,
}

#[derive(Serialize)]
pub struct AsmScanReport {
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
pub async fn assembly_scan(
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
