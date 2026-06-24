use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use maple_core::output::{export, offsets_header};
use maple_core::{BuildStamp, FindingStatus, ScanResult, arch_mismatch};

use crate::attach::attach_target;
use crate::cli::ScanArgs;
use crate::config::{Config, resolve_arch, resolve_attach, resolve_patterns, resolve_strict};
use crate::exit::{CliError, ExitKind, scan_exit_kind};
use crate::json::scan_json;
use crate::patterns::require_patterns;

#[allow(clippy::too_many_arguments)]
fn write_outputs(
    out: &Path,
    ce: bool,
    offsets: bool,
    result: &ScanResult,
    module: &str,
    base: u64,
    stamp: Option<&BuildStamp>,
    quiet: bool,
) -> Result<(), String> {
    std::fs::create_dir_all(out).map_err(|e| format!("create {}: {e}", out.display()))?;

    let header = stamp.map(BuildStamp::header_line);
    let update = out.join("update.txt");
    let contents = export(
        &result.findings,
        module,
        base,
        header.as_deref(),
        if ce { "ce" } else { "txt" },
    );
    if !quiet && update.exists() {
        eprintln!("[i] overwriting existing {}", update.display());
    }
    std::fs::write(&update, contents).map_err(|e| format!("write {}: {e}", update.display()))?;
    if !quiet {
        println!("[+] wrote {}", update.display());
    }

    if offsets {
        let header = out.join("offsets.h");
        if !quiet && header.exists() {
            eprintln!("[i] overwriting existing {}", header.display());
        }
        std::fs::write(&header, offsets_header(&result.findings, module, base))
            .map_err(|e| format!("write {}: {e}", header.display()))?;
        if !quiet {
            println!("[+] wrote {}", header.display());
        }
    }
    Ok(())
}

pub(crate) fn cmd_scan(a: ScanArgs, cfg: &Config) -> Result<ExitKind, CliError> {
    let json = a.json;
    let arch = resolve_arch(a.arch.as_deref(), cfg)?;
    let patterns_path = resolve_patterns(a.patterns.as_ref(), cfg);
    let out = a
        .out
        .clone()
        .or_else(|| cfg.out.clone())
        .unwrap_or_else(|| PathBuf::from("."));
    let strict = resolve_strict(a.lenient, cfg);
    let patterns = require_patterns(&patterns_path, arch, strict, json)?;

    let at = resolve_attach(&a.attach, cfg);
    let cancel = AtomicBool::new(false);
    let target = attach_target(&at, &cancel, json)?;
    if let Some(msg) = arch_mismatch(arch, target.module_arch(), &at.module) {
        return Err(CliError::new(ExitKind::InvalidInput, msg));
    }

    let regions = target.regions();
    // The module's executable regions, used both to validate a pattern's `@section` expectation
    // during the scan and to fingerprint the build below; enumerated once and reused.
    let code_regions = target.code_regions();
    if !json {
        println!("[+] scanning {} regions", regions.len());
    }
    let result = maple_core::scan_live(
        &target,
        target.module.base,
        target.module.size,
        &regions,
        &code_regions,
        &patterns,
        arch,
        None,
    );

    let mut stamp = BuildStamp::capture(&target, target.module.base, &code_regions);
    stamp.version = target.file_version();

    if json {
        // stdout is the JSON document only; everything else this command logged went to stderr.
        println!(
            "{}",
            scan_json(&result, &at.module, target.module.base as u64, &stamp)?
        );
    } else {
        println!();
        println!("[+] found {}", result.found.len());
        if !result.matched_unresolved.is_empty() {
            println!(
                "[!] matched but unresolved: {}",
                result.matched_unresolved.len()
            );
            for name in &result.matched_unresolved {
                println!("    {name}");
            }
        }
        if !result.not_found.is_empty() {
            println!("[-] not found: {}", result.not_found.len());
            for name in &result.not_found {
                println!("    {name}");
            }
        }
        let ambiguous: Vec<_> = result
            .rows
            .iter()
            .filter(|r| matches!(r.status, FindingStatus::FoundAmbiguous { .. }))
            .collect();
        if !ambiguous.is_empty() {
            println!(
                "[!] ambiguous (multiple matches, used the first): {}",
                ambiguous.len()
            );
            for r in &ambiguous {
                println!("    {} ({} matches)", r.name, r.matches);
            }
        }
        for w in &result.warnings {
            println!("[!] {w}");
        }
        println!("[+] total matches {}", result.total_matches);
        println!("[+] build {} ({} bytes)", stamp.short(), stamp.bytes);
    }

    // Duplicate symbol names collapse to one entry in the generated header (a C++ constant cannot be
    // declared twice). Surface that on stderr so a dropped row is not silent.
    let dups = maple_core::output::duplicate_names(&result.findings);
    if !dups.is_empty() {
        eprintln!(
            "[!] duplicate symbol name(s) collapsed in generated output: {}",
            dups.join(", ")
        );
    }

    write_outputs(
        &out,
        a.ce,
        !a.no_offsets,
        &result,
        &at.module,
        target.module.base as u64,
        Some(&stamp),
        json,
    )?;
    Ok(scan_exit_kind(&result))
}
