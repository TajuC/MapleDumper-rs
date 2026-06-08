use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use maple_core::output::{export, offsets_header};
use maple_core::pattern::{Arch, ParseSeverity, parse_patterns_file, parse_patterns_file_strict};
use maple_core::{
    AttachOptions, BuildStamp, DiffReport, FindingStatus, Locator, Pattern, ProfileReport,
    ResolveTrace, ScanResult, Target, arch_mismatch, assembly_scan, diff, lint, parse_asm_patterns,
    parse_dump, parse_stamp, profile,
};
use maple_core::{
    FileImage, HoldoutResult, ImageInput, NegativeEvidence, NegativeHit, SigCandidate, SigOptions,
    SigReport, TargetKind, TargetSpec, apply_negatives, generate, holdout_validate,
    make_string_anchor, negative_corpus_hits,
};

/// A stable process exit code. Automation can branch on the specific outcome instead of treating
/// every nonzero result the same. These numbers are part of the tool's contract; keep them stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExitKind {
    /// 0: ran cleanly with nothing to flag.
    Success,
    /// 2: completed with advisory issues only (lint flagged weak signatures; mksig matched a
    /// negative-corpus module).
    SuccessWithWarnings,
    /// 3: a scan ran but some patterns were not found or matched without resolving.
    Unresolved,
    /// 4: a scan ran but at least one pattern matched in several places.
    Ambiguous,
    /// 5: bad flags, bad config, bad/empty patterns, or the target could not be located.
    InvalidInput,
    /// 6: the target process could not be opened (try running as administrator).
    AccessDenied,
    /// 1: an unexpected failure.
    Internal,
}

impl ExitKind {
    fn code(self) -> u8 {
        match self {
            ExitKind::Success => 0,
            ExitKind::Internal => 1,
            ExitKind::SuccessWithWarnings => 2,
            ExitKind::Unresolved => 3,
            ExitKind::Ambiguous => 4,
            ExitKind::InvalidInput => 5,
            ExitKind::AccessDenied => 6,
        }
    }
}

/// A command failure carrying both a message and the exit code it should map to.
struct CliError {
    kind: ExitKind,
    msg: String,
}

impl CliError {
    fn new(kind: ExitKind, msg: impl Into<String>) -> Self {
        Self {
            kind,
            msg: msg.into(),
        }
    }
}

impl From<String> for CliError {
    /// Most string errors in this tool are user-actionable input, config or pattern problems, so a
    /// bare `?` maps to [`ExitKind::InvalidInput`]. The access-denied and internal cases are
    /// constructed explicitly where they arise (see [`attach_err`]).
    fn from(msg: String) -> Self {
        CliError::new(ExitKind::InvalidInput, msg)
    }
}

impl From<&str> for CliError {
    fn from(msg: &str) -> Self {
        CliError::new(ExitKind::InvalidInput, msg)
    }
}

/// Map an attach I/O failure to its exit code: a permission failure is access-denied, a missing
/// kernel primitive is internal, and "not running / timed out / module missing" is treated as an
/// input problem (the target specification did not resolve to a usable process).
fn attach_err(e: std::io::Error) -> CliError {
    let kind = match e.kind() {
        std::io::ErrorKind::PermissionDenied => ExitKind::AccessDenied,
        std::io::ErrorKind::Unsupported => ExitKind::Internal,
        _ => ExitKind::InvalidInput,
    };
    CliError::new(kind, format!("attach failed: {e}"))
}

/// The exit code that summarizes a finished scan: ambiguous beats unresolved beats
/// warnings-only beats clean.
fn scan_exit_kind(result: &ScanResult) -> ExitKind {
    if result
        .rows
        .iter()
        .any(|r| matches!(r.status, FindingStatus::FoundAmbiguous { .. }))
    {
        ExitKind::Ambiguous
    } else if !result.matched_unresolved.is_empty() || !result.not_found.is_empty() {
        ExitKind::Unresolved
    } else if !result.warnings.is_empty() {
        ExitKind::SuccessWithWarnings
    } else {
        ExitKind::Success
    }
}

#[derive(Parser)]
#[command(
    name = "mapledumper",
    version,
    about = "AOB/pattern scanner and offset dumper for Windows processes",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Config file of defaults (key = value); falls back to maple.conf in the working directory
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Attach to a process and dump offsets from a pattern file
    Scan(ScanArgs),
    /// Check a pattern file for weak signatures
    Lint(LintArgs),
    /// Compare two saved dumps and report what moved
    Diff(DiffArgs),
    /// Scan a live process by assembly instructions
    Asm(AsmArgs),
    /// Build a cross-version signature from client files on disk, no target needed
    Mksig(MksigArgs),
    /// Measure the read/scan/resolve split against a live target
    Profile(ProfileArgs),
}

#[derive(Args)]
struct AttachArgs {
    /// Attach by process name (.exe optional, case-insensitive)
    #[arg(long, value_name = "NAME")]
    process: Option<String>,
    /// Attach by top-level window class
    #[arg(long, value_name = "CLASS", conflicts_with = "process")]
    class: Option<String>,
    /// Attach by process id (use when several processes share a name)
    #[arg(long, value_name = "PID")]
    pid: Option<u32>,
    /// Module to scan (default: the process name)
    #[arg(long, value_name = "NAME")]
    module: Option<String>,
    /// Fail immediately if the target is not running
    #[arg(long)]
    no_wait: bool,
    /// Max seconds to wait for the target (0 = forever)
    #[arg(long, value_name = "SECS")]
    timeout: Option<u64>,
}

#[derive(Args)]
struct ScanArgs {
    #[command(flatten)]
    attach: AttachArgs,
    /// Pattern file (default: patterns.txt)
    #[arg(long, value_name = "FILE")]
    patterns: Option<PathBuf>,
    /// Architecture section to load (32 or 64)
    #[arg(long, value_name = "BITS")]
    arch: Option<String>,
    /// Output directory, created if missing (default: .)
    #[arg(long, value_name = "DIR")]
    out: Option<PathBuf>,
    /// Write update.txt as a Cheat Engine table
    #[arg(long)]
    ce: bool,
    /// Do not write offsets.h
    #[arg(long)]
    no_offsets: bool,
    /// Accept malformed pattern lines instead of failing (power-user opt-in)
    #[arg(long)]
    lenient: bool,
    /// Emit the scan result as JSON on stdout (progress goes to stderr)
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct LintArgs {
    /// Pattern file (default: patterns.txt)
    #[arg(long, value_name = "FILE")]
    patterns: Option<PathBuf>,
    /// Architecture section to load (32 or 64)
    #[arg(long, value_name = "BITS")]
    arch: Option<String>,
    /// Accept malformed pattern lines instead of failing
    #[arg(long)]
    lenient: bool,
    /// Emit the lint result as JSON on stdout
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct DiffArgs {
    /// The older dump file
    #[arg(value_name = "OLD")]
    old: PathBuf,
    /// The newer dump file
    #[arg(value_name = "NEW")]
    new: PathBuf,
}

#[derive(Args)]
struct AsmArgs {
    #[command(flatten)]
    attach: AttachArgs,
    /// Assembly file, one instruction per line, wildcards * ? ^ $
    #[arg(value_name = "FILE")]
    file: PathBuf,
    /// Architecture section to load (32 or 64)
    #[arg(long, value_name = "BITS")]
    arch: Option<String>,
    /// Only report matches at or above this address (hex)
    #[arg(long, value_name = "ADDR")]
    from: Option<String>,
    /// Only report matches below this address (hex)
    #[arg(long, value_name = "ADDR")]
    to: Option<String>,
}

#[derive(Args)]
struct MksigArgs {
    /// A client binary (repeat for each version)
    #[arg(long = "client", value_name = "EXE")]
    client: Vec<PathBuf>,
    /// Add every .exe in a folder as a client
    #[arg(long, value_name = "DIR")]
    client_dir: Option<PathBuf>,
    /// Target: locate this existing AOB in each client and harden it
    #[arg(long, value_name = "AOB")]
    sig: Option<String>,
    /// Target: a reference client, paired with --rva
    #[arg(long = "ref", value_name = "EXE")]
    ref_path: Option<PathBuf>,
    /// Target: an address in the reference client (hex)
    #[arg(long, value_name = "HEX")]
    rva: Option<String>,
    /// Reject signatures below this fixed-byte ratio (default 0.30)
    #[arg(long, value_name = "F")]
    min_fixed_ratio: Option<f64>,
    /// An unrelated module the chosen signature must NOT match (repeatable)
    #[arg(long = "negative", value_name = "EXE")]
    negative: Vec<PathBuf>,
    /// Add every .exe in a folder to the negative corpus
    #[arg(long, value_name = "DIR")]
    negative_dir: Option<PathBuf>,
    /// Leave-one-out check: regenerate from each subset and confirm the held-out build still matches
    #[arg(long)]
    holdout: bool,
    /// Print the full report as JSON
    #[arg(long)]
    json: bool,
    /// Write the JSON report to a file
    #[arg(long, value_name = "PATH")]
    json_out: Option<PathBuf>,
}

#[derive(Args)]
struct ProfileArgs {
    #[command(flatten)]
    attach: AttachArgs,
    /// Pattern file (default: patterns.txt)
    #[arg(long, value_name = "FILE")]
    patterns: Option<PathBuf>,
    /// Architecture section to load (32 or 64)
    #[arg(long, value_name = "BITS")]
    arch: Option<String>,
    /// Accept malformed pattern lines instead of failing
    #[arg(long)]
    lenient: bool,
}

#[derive(Default)]
struct Config {
    process: Option<String>,
    module: Option<String>,
    arch: Option<Arch>,
    patterns: Option<PathBuf>,
    out: Option<PathBuf>,
    strict: Option<bool>,
}

struct ResolvedAttach {
    process: Option<String>,
    class: Option<String>,
    pid: Option<u32>,
    module: String,
    wait: bool,
    timeout: Option<Duration>,
}

fn parse_bool(v: &str) -> Result<bool, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        other => Err(format!("expected a boolean, got '{other}'")),
    }
}

fn parse_hex_opt(field: &Option<String>) -> Result<Option<usize>, String> {
    match field.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(raw) => {
            let hex = raw.trim_start_matches("0x").trim_start_matches("0X");
            usize::from_str_radix(hex, 16)
                .map(Some)
                .map_err(|_| format!("invalid address '{raw}'"))
        }
    }
}

fn parse_arch(s: &str) -> Result<Arch, String> {
    Arch::parse(s)
}

fn parse_config(text: &str, label: &str) -> Result<Config, String> {
    let mut cfg = Config::default();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, val) = line
            .split_once('=')
            .ok_or_else(|| format!("{label}:{} expected key = value", n + 1))?;
        let (key, val) = (key.trim(), val.trim());
        match key {
            "process" | "process_name" => cfg.process = Some(val.to_string()),
            "module" | "module_name" => cfg.module = Some(val.to_string()),
            "arch" => {
                cfg.arch = Some(parse_arch(val).map_err(|e| format!("{label}:{} {e}", n + 1))?)
            }
            "patterns" => cfg.patterns = Some(PathBuf::from(val)),
            "out" | "outputs" => cfg.out = Some(PathBuf::from(val)),
            "strict" | "strict_patterns" => {
                cfg.strict = Some(parse_bool(val).map_err(|e| format!("{label}:{} {e}", n + 1))?);
            }
            other => return Err(format!("{label}:{} unknown key '{other}'", n + 1)),
        }
    }
    Ok(cfg)
}

fn load_config(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read config {}: {e}", path.display()))?;
    parse_config(&text, &path.display().to_string())
}

fn resolve_config(explicit: Option<&Path>) -> Result<Config, String> {
    if let Some(p) = explicit {
        return load_config(p);
    }
    let default = Path::new("maple.conf");
    if default.exists() {
        return load_config(default);
    }
    Ok(Config::default())
}

fn resolve_arch(cli: Option<&str>, cfg: &Config) -> Result<Arch, String> {
    match cli {
        Some(s) => parse_arch(s),
        None => Ok(cfg.arch.unwrap_or(Arch::X64)),
    }
}

fn resolve_strict(lenient: bool, cfg: &Config) -> bool {
    if lenient {
        return false;
    }
    cfg.strict.unwrap_or(true)
}

fn resolve_patterns(cli: Option<&PathBuf>, cfg: &Config) -> PathBuf {
    cli.cloned()
        .or_else(|| cfg.patterns.clone())
        .unwrap_or_else(|| PathBuf::from("patterns.txt"))
}

fn resolve_attach(a: &AttachArgs, cfg: &Config) -> ResolvedAttach {
    let (process, class) = if a.class.is_some() {
        (None, a.class.clone())
    } else if a.process.is_some() {
        (a.process.clone(), None)
    } else {
        (cfg.process.clone(), None)
    };
    let module = a
        .module
        .clone()
        .or_else(|| cfg.module.clone())
        .or_else(|| process.clone())
        .unwrap_or_else(|| "MapleStory.exe".to_string());
    let timeout = a
        .timeout
        .and_then(|s| (s > 0).then(|| Duration::from_secs(s)));
    ResolvedAttach {
        process,
        class,
        pid: a.pid,
        module,
        wait: !a.no_wait,
        timeout,
    }
}

fn locator(at: &ResolvedAttach) -> Result<Locator, String> {
    if let Some(process) = &at.process {
        Ok(Locator::Name(process.clone()))
    } else if let Some(class) = &at.class {
        Ok(Locator::Class(class.clone()))
    } else {
        Err("specify --process <name> or --class <window-class>".to_string())
    }
}

fn load_patterns(path: &Path, arch: Arch, strict: bool) -> Result<Vec<Pattern>, String> {
    if !strict {
        return parse_patterns_file(path, arch)
            .map_err(|e| format!("failed to read {}: {e}", path.display()));
    }
    let parsed = parse_patterns_file_strict(path, arch)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    match parsed {
        Ok(parsed) => {
            for w in &parsed.warnings {
                eprintln!("[!] {}:{} {}", path.display(), w.line, w.message);
            }
            Ok(parsed.patterns)
        }
        Err(issues) => {
            for issue in &issues {
                let tag = match issue.severity {
                    ParseSeverity::Error => "x",
                    ParseSeverity::Warning => "!",
                };
                eprintln!(
                    "[{tag}] {}:{} {}",
                    path.display(),
                    issue.line,
                    issue.message
                );
            }
            let errors = issues
                .iter()
                .filter(|i| i.severity == ParseSeverity::Error)
                .count();
            Err(format!("{errors} pattern error(s) in {}", path.display()))
        }
    }
}

fn require_patterns(
    path: &Path,
    arch: Arch,
    strict: bool,
    quiet: bool,
) -> Result<Vec<Pattern>, String> {
    let patterns = load_patterns(path, arch, strict)?;
    if patterns.is_empty() {
        return Err(format!("no patterns loaded from {}", path.display()));
    }
    if !quiet {
        println!("[+] loaded {} patterns", patterns.len());
    }
    Ok(patterns)
}

fn attach_target(
    at: &ResolvedAttach,
    cancel: &AtomicBool,
    quiet: bool,
) -> Result<Target, CliError> {
    let opts = AttachOptions {
        wait: at.wait,
        timeout: at.timeout,
        poll: Duration::from_millis(300),
    };
    let target = if let Some(pid) = at.pid {
        if !quiet {
            println!("[+] attaching to pid {pid}");
        }
        Target::attach_pid(pid, &at.module).map_err(attach_err)?
    } else {
        let loc = locator(at)?;
        if let Locator::Name(name) = &loc {
            let candidates = maple_core::process::process_candidates(name);
            if candidates.len() > 1 {
                // A multiple-match warning matters even in --json mode, so it goes to stderr (where
                // it cannot corrupt a piped JSON document on stdout) rather than being suppressed.
                eprintln!("[!] {} processes match '{name}':", candidates.len());
                for c in &candidates {
                    eprintln!(
                        "      pid {}  {}",
                        c.pid,
                        c.path.as_deref().unwrap_or("(path unavailable)")
                    );
                }
                eprintln!("    attaching to the first; pass --pid <pid> to choose another");
            }
        }
        if at.wait && !quiet {
            let what = match &loc {
                Locator::Name(name) => format!("process {name}"),
                Locator::Class(class) => format!("window class {class}"),
            };
            println!("[*] waiting for {what} (Ctrl-C to cancel)...");
        }
        Target::attach(&loc, &at.module, &opts, cancel).map_err(attach_err)?
    };
    if !quiet {
        println!(
            "[+] attached; module {} base 0x{:X} size 0x{:X}",
            at.module, target.module.base, target.module.size
        );
    }
    Ok(target)
}

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

#[derive(Serialize)]
struct ScanFindingJson {
    name: String,
    category: String,
    status: String,
    value: Option<String>,
    is_offset: bool,
    matches: usize,
    confidence: u8,
    candidates: Vec<String>,
    trace: Option<String>,
    // The full structured resolution trace (instruction offset, operand, mnemonic, target, checks,
    // failure reason), so automation can inspect why a value resolved, not just the one-liner.
    trace_detail: Option<ResolveTrace>,
    exported: bool,
}

#[derive(Serialize)]
struct ScanJson {
    module: String,
    module_base: String,
    build_hash: String,
    build_version: Option<String>,
    found: usize,
    unresolved: usize,
    not_found: usize,
    ambiguous: usize,
    total_matches: usize,
    unread_bytes: u64,
    warnings: Vec<String>,
    findings: Vec<ScanFindingJson>,
}

fn scan_json(result: &ScanResult, module: &str, base: u64, stamp: &BuildStamp) -> String {
    let ambiguous = result
        .rows
        .iter()
        .filter(|r| matches!(r.status, FindingStatus::FoundAmbiguous { .. }))
        .count();
    let findings = result
        .rows
        .iter()
        .map(|r| ScanFindingJson {
            name: r.name.clone(),
            category: r.category.clone(),
            status: r.status.label().to_string(),
            value: r.value.map(|v| format!("0x{v:X}")),
            is_offset: r.is_offset,
            matches: r.matches,
            confidence: r.confidence,
            candidates: r.candidates.iter().map(|v| format!("0x{v:X}")).collect(),
            trace: r.trace.clone(),
            trace_detail: r.trace_detail.clone(),
            // An ambiguous or failed row is shown for inspection but is never written as an offset.
            exported: r.status.is_exportable(),
        })
        .collect();
    let report = ScanJson {
        module: module.to_string(),
        module_base: format!("0x{base:X}"),
        build_hash: stamp.short(),
        build_version: stamp.version.clone(),
        found: result.found.len(),
        unresolved: result.matched_unresolved.len(),
        not_found: result.not_found.len(),
        ambiguous,
        total_matches: result.total_matches,
        unread_bytes: result.unread_bytes(),
        warnings: result.warnings.clone(),
        findings,
    };
    serde_json::to_string_pretty(&report).unwrap_or_default()
}

fn cmd_scan(a: ScanArgs, cfg: &Config) -> Result<ExitKind, CliError> {
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
    );

    let mut stamp = BuildStamp::capture(&target, target.module.base, &code_regions);
    stamp.version = target.file_version();

    if json {
        // stdout is the JSON document only; everything else this command logged went to stderr.
        println!(
            "{}",
            scan_json(&result, &at.module, target.module.base as u64, &stamp)
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

#[derive(Serialize)]
struct LintJson {
    name: String,
    aob: String,
    lints: Vec<String>,
}

fn cmd_lint(a: LintArgs, cfg: &Config) -> Result<ExitKind, CliError> {
    let arch = resolve_arch(a.arch.as_deref(), cfg)?;
    let patterns_path = resolve_patterns(a.patterns.as_ref(), cfg);
    let strict = resolve_strict(a.lenient, cfg);
    let patterns = require_patterns(&patterns_path, arch, strict, a.json)?;
    let flagged = if a.json {
        let report: Vec<LintJson> = patterns
            .iter()
            .map(|p| LintJson {
                name: p.name.clone(),
                aob: p.signature.to_aob(),
                lints: lint(&p.signature).iter().map(|l| l.message()).collect(),
            })
            .collect();
        let flagged = report.iter().filter(|r| !r.lints.is_empty()).count();
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        flagged
    } else {
        print_lints(&patterns)
    };
    Ok(if flagged > 0 {
        ExitKind::SuccessWithWarnings
    } else {
        ExitKind::Success
    })
}

fn cmd_diff(a: DiffArgs) -> Result<ExitKind, CliError> {
    let old_text =
        std::fs::read_to_string(&a.old).map_err(|e| format!("read {}: {e}", a.old.display()))?;
    let new_text =
        std::fs::read_to_string(&a.new).map_err(|e| format!("read {}: {e}", a.new.display()))?;
    print_build_compare(
        parse_stamp(&old_text).as_ref(),
        parse_stamp(&new_text).as_ref(),
    );
    print_diff(&diff(&parse_dump(&old_text), &parse_dump(&new_text)));
    Ok(ExitKind::Success)
}

fn cmd_asm(a: AsmArgs, cfg: &Config) -> Result<ExitKind, CliError> {
    let arch = resolve_arch(a.arch.as_deref(), cfg)?;
    let at = resolve_attach(&a.attach, cfg);
    let cancel = AtomicBool::new(false);
    let target = attach_target(&at, &cancel, false)?;
    if let Some(msg) = arch_mismatch(arch, target.module_arch(), &at.module) {
        return Err(CliError::new(ExitKind::InvalidInput, msg));
    }

    let text =
        std::fs::read_to_string(&a.file).map_err(|e| format!("read {}: {e}", a.file.display()))?;
    let pat = parse_asm_patterns(&text)
        .ok_or_else(|| format!("no assembly lines in {}", a.file.display()))?;
    let from = parse_hex_opt(&a.from)?;
    let to = parse_hex_opt(&a.to)?;
    let regions = maple_core::memory::clip_regions(&target.code_regions(), from, to);
    println!("[+] assembly scan over {} regions", regions.len());
    let hits = assembly_scan(&target, target.module.base, &regions, arch, &pat, &cancel);
    println!("[+] {} matches", hits.len());
    for h in &hits {
        let bytes = h
            .bytes
            .iter()
            .map(|b| format!("{b:02X} "))
            .collect::<String>();
        println!("  0x{:X} (+0x{:X})  {}", h.address, h.rva, bytes.trim_end());
        for line in &h.lines {
            println!("      {line}");
        }
    }
    Ok(ExitKind::Success)
}

fn cmd_profile(a: ProfileArgs, cfg: &Config) -> Result<ExitKind, CliError> {
    let arch = resolve_arch(a.arch.as_deref(), cfg)?;
    let patterns_path = resolve_patterns(a.patterns.as_ref(), cfg);
    let strict = resolve_strict(a.lenient, cfg);
    let patterns = require_patterns(&patterns_path, arch, strict, false)?;

    let at = resolve_attach(&a.attach, cfg);
    let cancel = AtomicBool::new(false);
    let target = attach_target(&at, &cancel, false)?;
    if let Some(msg) = arch_mismatch(arch, target.module_arch(), &at.module) {
        return Err(CliError::new(ExitKind::InvalidInput, msg));
    }

    let regions = target.code_regions();
    println!(
        "[*] profiling {} executable regions (runs several full reads, give it a few seconds)...",
        regions.len()
    );
    let report = profile(
        &target,
        target.module.base,
        target.module.size,
        &regions,
        &patterns,
        arch,
    );
    print_profile(&report);
    Ok(ExitKind::Success)
}

fn run() -> Result<ExitKind, CliError> {
    let cli = Cli::parse();
    let cfg = resolve_config(cli.config.as_deref())?;
    match cli.command {
        Command::Scan(a) => cmd_scan(a, &cfg),
        Command::Lint(a) => cmd_lint(a, &cfg),
        Command::Diff(a) => cmd_diff(a),
        Command::Asm(a) => cmd_asm(a, &cfg),
        Command::Mksig(a) => cmd_mksig(a),
        Command::Profile(a) => cmd_profile(a, &cfg),
    }
}

fn gbps(bytes: u64, ms: u128) -> f64 {
    if ms == 0 {
        return 0.0;
    }
    bytes as f64 / (ms as f64 / 1000.0) / 1_073_741_824.0
}

fn print_profile(r: &ProfileReport) {
    let mb = r.bytes as f64 / 1_048_576.0;
    println!();
    println!(
        "==== profile: {mb:.0} MB across {} executable regions | {} patterns | {} cores ====",
        r.regions, r.patterns, r.cores
    );
    println!();
    println!("read-only (cross-process copy, no scan):");
    for (readers, ms) in &r.read_ms {
        println!(
            "  {readers} reader(s): {ms:>6} ms  ({:.2} GB/s)",
            gbps(r.bytes, *ms)
        );
    }
    println!();
    println!("scan-only on a local buffer (no reads):");
    println!(
        "  serial  (1 thread)   : {:>6} ms  ({:.2} GB/s)  [single-thread baseline; the real",
        r.scan_serial_ms,
        gbps(r.bytes, r.scan_serial_ms)
    );
    println!("                          parallel scan is measured in the full pipeline below]");
    println!("  matches: {}", r.matches);
    println!();
    println!(
        "resolve-only           : {:>6} ms  (_CALL hits doing extra reads: {})",
        r.resolve_ms, r.call_hits
    );
    println!();
    println!("full pipeline (read + scan + resolve overlapped):");
    println!(
        "  default chunk        : {:>6} ms  ({:.2} GB/s end-to-end)",
        r.full_ms,
        gbps(r.bytes, r.full_ms)
    );
    println!("  chunk-size sweep:");
    for (size, ms) in &r.chunk_ms {
        println!("    {:>5} KiB: {ms:>6} ms", size >> 10);
    }
    println!();
    let read1 = r.read_ms.first().map_or(0, |&(_, ms)| ms);
    println!(
        "verdict: read(1) {read1} ms | scan(serial) {} ms | resolve {} ms | full {} ms",
        r.scan_serial_ms, r.resolve_ms, r.full_ms
    );
    if r.full_ms > 0 && read1 as f64 >= 0.80 * r.full_ms as f64 {
        println!(
            "         read-bound: the read alone is ~{:.0}% of the full pipeline; the scan hides under it.",
            100.0 * read1 as f64 / r.full_ms as f64
        );
    } else {
        println!(
            "         not purely read-bound: scan/resolve are a meaningful fraction, so matcher work may pay off."
        );
    }
}

fn print_build_compare(old: Option<&BuildStamp>, new: Option<&BuildStamp>) {
    if let (Some(a), Some(b)) = (old, new) {
        let state = if a.hash == b.hash { "same" } else { "changed" };
        println!("[i] build {} -> {} ({state})", a.short(), b.short());
        if a.version.is_some() || b.version.is_some() {
            println!(
                "    version {} -> {}",
                a.version.as_deref().unwrap_or("?"),
                b.version.as_deref().unwrap_or("?")
            );
        }
    }
}

fn print_lints(patterns: &[Pattern]) -> usize {
    let mut flagged = 0;
    for p in patterns {
        let lints = lint(&p.signature);
        if lints.is_empty() {
            continue;
        }
        flagged += 1;
        println!("[!] {}", p.name);
        for l in &lints {
            println!("      {}", l.message());
        }
    }
    println!();
    println!(
        "[+] {} patterns, {flagged} flagged, {} clean",
        patterns.len(),
        patterns.len() - flagged
    );
    flagged
}

fn print_diff(report: &DiffReport) {
    println!("[=] {} unchanged", report.unchanged);
    if !report.moved.is_empty() {
        println!("[~] {} moved:", report.moved.len());
        for m in &report.moved {
            println!("      {} 0x{:X} -> 0x{:X}", m.name, m.old, m.new);
        }
    }
    if !report.added.is_empty() {
        println!("[+] {} new:", report.added.len());
        for f in &report.added {
            println!("      {} 0x{:X}", f.name, f.value);
        }
    }
    if !report.removed.is_empty() {
        println!("[-] {} removed:", report.removed.len());
        for f in &report.removed {
            println!("      {} 0x{:X}", f.name, f.value);
        }
    }
}

fn arch_str(arch: Arch) -> &'static str {
    if matches!(arch, Arch::X64) {
        "x64"
    } else {
        "x86"
    }
}

fn kind_str(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Code => "code",
        TargetKind::Data => "data",
        TargetKind::Import => "import",
        TargetKind::Unknown => "unknown",
    }
}

fn file_label(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn collect_clients(
    clients: &[PathBuf],
    client_dir: Option<&Path>,
    ref_path: Option<&Path>,
) -> Result<Vec<PathBuf>, String> {
    let mut clients = clients.to_vec();
    if let Some(dir) = client_dir {
        let rd = std::fs::read_dir(dir).map_err(|e| format!("read dir {}: {e}", dir.display()))?;
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")) {
                clients.push(p);
            }
        }
    }
    if let Some(r) = ref_path {
        clients.push(r.to_path_buf());
    }
    clients.sort();
    clients.dedup();
    if clients.is_empty() {
        return Err("mksig needs at least one --client or --client-dir".to_string());
    }
    Ok(clients)
}

fn gather_negatives(files: &[PathBuf], dir: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    let mut out = files.to_vec();
    if let Some(d) = dir {
        let rd = std::fs::read_dir(d).map_err(|e| format!("read dir {}: {e}", d.display()))?;
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")) {
                out.push(p);
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[derive(Serialize)]
struct JPer {
    label: String,
    match_rva: Option<String>,
    resolved_target_rva: Option<String>,
    target_type: Option<String>,
    fingerprint_similarity: Option<f64>,
    /// A fresh byte signature minted for this build at the relocated address, when the cross-build AOB
    /// does not apply (a recompiled build located by string/encoding/fingerprint anchor).
    aob: Option<String>,
}
#[derive(Serialize)]
struct JScores {
    uniqueness: u32,
    stability: u32,
    entropy: u32,
    semantic: u32,
    resolver_confidence: u32,
    cross_build: u32,
    final_score: u32,
}
#[derive(Serialize)]
struct JCand {
    aob: String,
    suffix: String,
    grade: String,
    score: u32,
    scores: JScores,
    reasons: Vec<String>,
    bytes: usize,
    fixed: usize,
    wildcards: usize,
    fixed_ratio: f64,
    reloc_safe: bool,
    per_version: Vec<JPer>,
    diags: Vec<String>,
}
#[derive(Serialize)]
struct JInput {
    label: String,
    packed: bool,
    reasons: Vec<String>,
}
#[derive(Serialize)]
struct JDup {
    code_hash: String,
    labels: Vec<String>,
}
#[derive(Serialize)]
struct JNeg {
    label: String,
    count: usize,
}
#[derive(Serialize)]
struct JNegSummary {
    modules_scanned: usize,
    modules_hit: usize,
    total_hits: usize,
    max_hits_per_module: usize,
}
#[derive(Serialize)]
struct JHold {
    held_out: String,
    generated: bool,
    matched: bool,
}
#[derive(Serialize)]
struct JShortEntry {
    rva: String,
    similarity: f64,
    aob: Option<String>,
}
#[derive(Serialize)]
struct JShortlist {
    label: String,
    candidates: Vec<JShortEntry>,
}
#[derive(Serialize)]
struct JAobRange {
    aob: String,
    minted_in: String,
    first: String,
    last: String,
    labels: Vec<String>,
}
#[derive(Serialize)]
struct JReport {
    arch: String,
    unique_builds: usize,
    inputs: Vec<JInput>,
    duplicate_groups: Vec<JDup>,
    chosen: Option<JCand>,
    alternates: Vec<JCand>,
    rejected: Vec<JCand>,
    negative_hits: Vec<JNeg>,
    negative_summary: JNegSummary,
    holdout: Vec<JHold>,
    string_anchor: Option<String>,
    shortlists: Vec<JShortlist>,
    aob_ranges: Vec<JAobRange>,
    diagnostics: Vec<String>,
}

fn jcand(c: &SigCandidate) -> JCand {
    JCand {
        aob: c.aob.clone(),
        suffix: c.suffix.as_str().to_string(),
        grade: c.grade.letter().to_string(),
        score: c.score,
        scores: JScores {
            uniqueness: c.scores.uniqueness,
            stability: c.scores.stability,
            entropy: c.scores.entropy,
            semantic: c.scores.semantic,
            resolver_confidence: c.scores.resolver_confidence,
            cross_build: c.scores.cross_build,
            final_score: c.scores.final_score,
        },
        reasons: c.reasons.clone(),
        bytes: c.bytes_len,
        fixed: c.fixed,
        wildcards: c.wildcards,
        fixed_ratio: c.fixed_ratio,
        reloc_safe: c.reloc_safe,
        per_version: c
            .per_version
            .iter()
            .map(|p| JPer {
                label: p.label.clone(),
                match_rva: p.match_rva.map(|v| format!("0x{v:X}")),
                resolved_target_rva: p.resolved_target_rva.map(|v| format!("0x{v:X}")),
                target_type: p.target_kind.map(|k| kind_str(k).to_string()),
                fingerprint_similarity: p.fingerprint_similarity,
                aob: p.aob.clone(),
            })
            .collect(),
        diags: c.diags.iter().map(|d| d.to_string()).collect(),
    }
}

fn json_report(
    r: &SigReport,
    negatives: &[NegativeHit],
    negatives_scanned: usize,
    holdout: &[HoldoutResult],
    string_anchor: Option<&str>,
) -> String {
    let neg_counts: Vec<usize> = negatives.iter().map(|h| h.count).collect();
    let neg_summary = NegativeEvidence::from_hits(negatives_scanned, &neg_counts);
    let report = JReport {
        arch: arch_str(r.arch).to_string(),
        unique_builds: r.unique_builds,
        inputs: r
            .inputs
            .iter()
            .map(|i| JInput {
                label: i.label.clone(),
                packed: i.packed,
                reasons: i.reasons.clone(),
            })
            .collect(),
        duplicate_groups: r
            .duplicate_groups
            .iter()
            .map(|g| JDup {
                code_hash: format!("{:016X}", g.code_hash),
                labels: g.labels.clone(),
            })
            .collect(),
        chosen: r.chosen.as_ref().map(jcand),
        alternates: r.alternates.iter().map(jcand).collect(),
        rejected: r.rejected.iter().map(jcand).collect(),
        negative_hits: negatives
            .iter()
            .map(|h| JNeg {
                label: h.label.clone(),
                count: h.count,
            })
            .collect(),
        negative_summary: JNegSummary {
            modules_scanned: neg_summary.modules_scanned,
            modules_hit: neg_summary.modules_hit,
            total_hits: neg_summary.total_hits,
            max_hits_per_module: neg_summary.max_hits_per_module,
        },
        holdout: holdout
            .iter()
            .map(|h| JHold {
                held_out: h.held_out.clone(),
                generated: h.generated,
                matched: h.matched_holdout,
            })
            .collect(),
        string_anchor: string_anchor.map(str::to_string),
        shortlists: r
            .shortlists
            .iter()
            .map(|s| JShortlist {
                label: s.label.clone(),
                candidates: s
                    .entries
                    .iter()
                    .map(|e| JShortEntry {
                        rva: format!("0x{:X}", e.rva),
                        similarity: e.similarity,
                        aob: e.aob.clone(),
                    })
                    .collect(),
            })
            .collect(),
        aob_ranges: r
            .aob_ranges
            .iter()
            .map(|rg| JAobRange {
                aob: rg.aob.clone(),
                minted_in: rg.minted_in.clone(),
                first: rg.first_label.clone(),
                last: rg.last_label.clone(),
                labels: rg.labels.clone(),
            })
            .collect(),
        diagnostics: r.diagnostics.iter().map(|d| d.to_string()).collect(),
    };
    serde_json::to_string_pretty(&report).unwrap_or_default()
}

fn print_candidate(tag: &str, c: &SigCandidate) {
    println!(
        "[{tag}] grade {} {}{}",
        c.grade.letter(),
        c.aob,
        c.suffix.as_str()
    );
    println!(
        "      score {} (final), {} bytes, {} fixed, {} wild, ratio {:.2}, reloc_safe {}",
        c.score, c.bytes_len, c.fixed, c.wildcards, c.fixed_ratio, c.reloc_safe
    );
    let s = &c.scores;
    println!(
        "      sub-scores: uniqueness {} stability {} entropy {} semantic {} resolver {} cross-build {}",
        s.uniqueness, s.stability, s.entropy, s.semantic, s.resolver_confidence, s.cross_build
    );
    for p in &c.per_version {
        let m = p
            .match_rva
            .map_or_else(|| "-".to_string(), |v| format!("0x{v:X}"));
        let t = p
            .resolved_target_rva
            .map_or_else(String::new, |v| format!(" -> 0x{v:X}"));
        let sim = p
            .fingerprint_similarity
            .map_or_else(String::new, |v| format!(" (callee ~{:.0}%)", v * 100.0));
        println!("        {} @ {m}{t}{sim}", p.label);
    }
    for r in &c.reasons {
        println!("        - {r}");
    }
    for d in &c.diags {
        println!("        ! {d}");
    }
}

fn print_sig_report(r: &SigReport, opts: &SigOptions) {
    println!(
        "[+] arch {} | {} unique build(s)",
        arch_str(r.arch),
        r.unique_builds
    );
    println!(
        "    gates: min_fixed {}, min_fixed_ratio {:.2}, max_len {}",
        opts.min_fixed, opts.min_fixed_ratio, opts.max_len
    );
    for g in &r.duplicate_groups {
        if g.labels.len() > 1 {
            println!(
                "    duplicate build {:016X}: {}",
                g.code_hash,
                g.labels.join(", ")
            );
        }
    }
    match &r.chosen {
        Some(c) => print_candidate("chosen", c),
        None => println!("[-] no safe signature found"),
    }
    if !r.aob_ranges.is_empty() {
        println!("    version coverage (a fresh AOB is minted where the bytes break):");
        for rg in &r.aob_ranges {
            let span = if rg.first_label == rg.last_label {
                rg.first_label.clone()
            } else {
                format!("{} .. {}", rg.first_label, rg.last_label)
            };
            println!("      {span}  ({} build(s)):  {}", rg.labels.len(), rg.aob);
        }
    }
    for c in &r.alternates {
        print_candidate("alt", c);
    }
    for c in &r.rejected {
        print_candidate("rejected", c);
    }
    for d in &r.diagnostics {
        println!("    note: {d}");
    }
}

fn cmd_mksig(m: MksigArgs) -> Result<ExitKind, CliError> {
    let clients = collect_clients(&m.client, m.client_dir.as_deref(), m.ref_path.as_deref())?;
    let has_sig = m.sig.is_some();
    let has_ref = m.ref_path.is_some() || m.rva.is_some();
    if has_sig == has_ref {
        return Err("provide exactly one of --sig OR (--ref + --rva)".into());
    }
    if let Some(aob) = &m.sig {
        maple_core::try_signature_from_aob(aob).map_err(|e| format!("invalid --sig: {e}"))?;
    }

    let images: Vec<FileImage> = clients
        .iter()
        .map(|p| FileImage::open(p).map_err(|e| format!("open {}: {e}", p.display())))
        .collect::<Result<_, _>>()?;
    let reports: Vec<_> = images.iter().map(FileImage::pack_report).collect();

    for (p, pr) in clients.iter().zip(&reports) {
        if pr.likely_packed {
            eprintln!(
                "[!] {} looks packed ({}, entropy {:.2}) - generated signatures may be unreliable",
                p.display(),
                pr.reasons.join("; "),
                pr.max_code_entropy
            );
        }
    }

    let mut inputs = Vec::with_capacity(images.len());
    for (k, img) in images.iter().enumerate() {
        inputs.push(ImageInput {
            label: file_label(&clients[k]),
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

    let spec = if let Some(aob) = &m.sig {
        TargetSpec::Aob(aob.clone())
    } else {
        let rva = parse_hex_opt(&m.rva)?.ok_or("--rva <hex> is required with --ref")? as u64;
        let ref_path = m.ref_path.as_ref().ok_or("--ref <exe> is required")?;
        let idx = clients
            .iter()
            .position(|c| c == ref_path)
            .ok_or("the --ref file was not opened as a client")?;
        TargetSpec::Ref { image: idx, rva }
    };

    let mut opts = SigOptions::default();
    if let Some(r) = m.min_fixed_ratio {
        opts.min_fixed_ratio = r;
    }

    let mut report = generate(&inputs, &spec, &opts);

    let anchor_line = report.chosen.as_ref().and_then(|c| {
        let anchor = c.per_version.iter().find_map(|pv| {
            let rva = pv.match_rva?;
            let img = inputs.iter().find(|i| i.label == pv.label)?;
            make_string_anchor(img, rva as usize)
        })?;
        Some(match &anchor.also {
            Some(also) => format!("@string={} @also={also}", anchor.text),
            None => format!("@string={}", anchor.text),
        })
    });

    let holdout = if m.holdout {
        holdout_validate(&inputs, &spec, &opts)
    } else {
        Vec::new()
    };

    let neg_paths = gather_negatives(&m.negative, m.negative_dir.as_deref())?;
    let neg_hits = match &report.chosen {
        Some(chosen) if !neg_paths.is_empty() => {
            let neg_images: Vec<FileImage> = neg_paths
                .iter()
                .map(|p| {
                    FileImage::open(p).map_err(|e| format!("open negative {}: {e}", p.display()))
                })
                .collect::<Result<_, _>>()?;
            let neg_inputs: Vec<ImageInput> = neg_images
                .iter()
                .enumerate()
                .map(|(k, img)| ImageInput {
                    label: file_label(&neg_paths[k]),
                    source: img,
                    base: img.base(),
                    size: img.size(),
                    code_regions: img.code_regions(),
                    regions: img.regions(),
                    import: img.import_range(),
                    arch: img.arch(),
                    code_hash: img.code_hash(),
                    packed: false,
                    pack_reasons: Vec::new(),
                    reloc: Some(img),
                })
                .collect();
            negative_corpus_hits(&chosen.aob, &neg_inputs)
        }
        _ => Vec::new(),
    };

    // A signature that also matches unrelated modules is too generic to trust as an identity, so
    // fold that into the chosen candidate's uniqueness/final score (and possibly its grade) before
    // reporting, rather than only noting it alongside. The evidence carries how many modules were
    // scanned, how many matched, and the match volume, so the downgrade is honest about its basis.
    if !neg_hits.is_empty()
        && let Some(chosen) = report.chosen.as_mut()
    {
        let hit_counts: Vec<usize> = neg_hits.iter().map(|h| h.count).collect();
        apply_negatives(chosen, neg_paths.len(), &hit_counts);
    }

    if m.json || m.json_out.is_some() {
        let json = json_report(
            &report,
            &neg_hits,
            neg_paths.len(),
            &holdout,
            anchor_line.as_deref(),
        );
        if let Some(path) = &m.json_out {
            std::fs::write(path, &json).map_err(|e| format!("write {}: {e}", path.display()))?;
            eprintln!("[+] wrote {}", path.display());
        }
        if m.json {
            println!("{json}");
        }
    } else {
        print_sig_report(&report, &opts);
    }

    if let Some(line) = &anchor_line {
        eprintln!("[+] string anchor (survives client patches): NewSig = {line}");
    }

    // Validation summaries go to stderr so a piped --json stdout stays pure JSON.
    if neg_hits.is_empty() {
        if report.chosen.is_some() && !neg_paths.is_empty() {
            eprintln!("[+] clean against {} negative module(s)", neg_paths.len());
        }
    } else {
        eprintln!(
            "[!] the chosen signature also matches {} unrelated module(s):",
            neg_hits.len()
        );
        for h in &neg_hits {
            let plural = if h.count == 1 { "" } else { "es" };
            eprintln!("      {} ({} match{plural})", h.label, h.count);
        }
    }

    if m.holdout {
        if holdout.is_empty() {
            eprintln!("[i] holdout needs at least 3 builds; skipped");
        } else {
            let passed = holdout.iter().filter(|r| r.matched_holdout).count();
            eprintln!(
                "[+] holdout: {passed}/{} held-out build(s) re-matched",
                holdout.len()
            );
            for r in &holdout {
                let verdict = if r.matched_holdout {
                    "ok"
                } else if r.generated {
                    "MISS, signature did not match the held-out build"
                } else {
                    "no signature from the remaining builds"
                };
                eprintln!("      hold out {}: {verdict}", r.held_out);
            }
        }
    }
    // No safe signature is an unresolved outcome; a chosen one that also hits the negative corpus is
    // a warning (too generic to trust as an identity); otherwise a clean success.
    Ok(if report.chosen.is_none() {
        ExitKind::Unresolved
    } else if !neg_hits.is_empty() {
        ExitKind::SuccessWithWarnings
    } else {
        ExitKind::Success
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(kind) => ExitCode::from(kind.code()),
        Err(e) => {
            eprintln!("[error] {}", e.msg);
            ExitCode::from(e.kind.code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maple_core::{Grade, PatternRow, PerVersion, SubScores, Suffix};

    fn mkrow(name: &str, status: FindingStatus, candidates: Vec<u64>) -> PatternRow {
        PatternRow {
            name: name.to_string(),
            category: "globals".to_string(),
            pattern: "48 8B ?? ??".to_string(),
            value: candidates.first().copied(),
            is_offset: false,
            matches: candidates.len(),
            status,
            note: String::new(),
            candidates,
            confidence: 0,
            trace: None,
            trace_detail: None,
        }
    }

    fn result_of(rows: Vec<PatternRow>, unresolved: Vec<&str>, not_found: Vec<&str>) -> ScanResult {
        let found = rows
            .iter()
            .filter(|r| r.status.is_found())
            .map(|r| r.name.clone())
            .collect();
        let total_matches = rows.iter().map(|r| r.matches).sum();
        ScanResult {
            findings: Vec::new(),
            rows,
            found,
            matched_unresolved: unresolved.iter().map(|s| s.to_string()).collect(),
            not_found: not_found.iter().map(|s| s.to_string()).collect(),
            total_matches,
            read_gaps: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn json_report_pins_the_address_and_field_contract() {
        use maple_core::sigmaker::{AobRange, Shortlist, ShortlistEntry};
        use maple_core::{
            Diag, DupGroup, HoldoutResult, InputInfo, NegativeHit, SigCandidate, SigReport,
            TargetKind,
        };
        use serde_json::Value;

        let chosen = SigCandidate {
            aob: "48 8B 05 ?? ?? ?? ??".to_string(),
            suffix: Suffix::Call,
            grade: Grade::A,
            score: 84,
            bytes_len: 16,
            fixed: 9,
            wildcards: 7,
            fixed_ratio: 0.5625,
            reloc_safe: true,
            gated: false,
            packed: false,
            scores: SubScores {
                uniqueness: 90,
                stability: 80,
                entropy: 70,
                semantic: 60,
                resolver_confidence: 88,
                cross_build: 77,
                final_score: 84,
            },
            reasons: vec!["unique across corpus".to_string()],
            per_version: vec![PerVersion {
                label: "v83".to_string(),
                match_rva: Some(0x0040_1000),
                resolved_target_rva: Some(0x0040_2ABC),
                target_kind: Some(TargetKind::Code),
                fingerprint_similarity: Some(0.95),
                aob: Some("AA BB CC".to_string()),
            }],
            diags: vec![Diag::CalleeMismatch],
        };
        let report = SigReport {
            arch: Arch::X64,
            inputs: vec![InputInfo {
                label: "v83".to_string(),
                packed: false,
                reasons: vec![],
            }],
            unique_builds: 1,
            duplicate_groups: vec![DupGroup {
                code_hash: 0xDEAD_BEEF,
                labels: vec!["v83".to_string(), "v84".to_string()],
            }],
            chosen: Some(chosen),
            alternates: vec![],
            rejected: vec![],
            shortlists: vec![Shortlist {
                label: "v95".to_string(),
                entries: vec![ShortlistEntry {
                    rva: 0x0040_10F0,
                    similarity: 0.81,
                    aob: None,
                }],
            }],
            aob_ranges: vec![AobRange {
                aob: "48 8B".to_string(),
                minted_in: "v83".to_string(),
                first_label: "v83".to_string(),
                last_label: "v88".to_string(),
                labels: vec!["v83".to_string(), "v88".to_string()],
            }],
            diagnostics: vec![Diag::NotUnique],
        };
        let negatives = vec![NegativeHit {
            label: "kernel32.dll".to_string(),
            count: 2,
        }];
        let holdout = vec![HoldoutResult {
            held_out: "v84".to_string(),
            generated: true,
            matched_holdout: true,
        }];

        let json = json_report(&report, &negatives, 5, &holdout, Some("@anchor"));
        let v: Value = serde_json::from_str(&json).expect("--json output must be valid JSON");

        // Addresses serialize as hex strings, never integers. This is the load-bearing part of the
        // --json contract: a consumer parses "0x401000", not 4198400. The eventual Serialize refactor
        // must preserve it (a plain derive on the u64 fields would silently break every consumer).
        assert_eq!(v["arch"], "x64");
        assert_eq!(v["duplicate_groups"][0]["code_hash"], "00000000DEADBEEF");
        let pv = &v["chosen"]["per_version"][0];
        assert_eq!(pv["match_rva"], "0x401000");
        assert_eq!(pv["resolved_target_rva"], "0x402ABC");
        assert_eq!(pv["target_type"], "code");
        assert_eq!(v["shortlists"][0]["candidates"][0]["rva"], "0x4010F0");

        // Field names the core types do not themselves carry are pinned here.
        assert_eq!(v["chosen"]["bytes"], 16);
        assert!(v["chosen"].get("bytes_len").is_none());
        assert_eq!(v["holdout"][0]["matched"], true);
        assert!(v["holdout"][0].get("matched_holdout").is_none());

        // negative_summary is derived CLI-side from the raw per-module hit counts.
        assert_eq!(v["negative_summary"]["modules_scanned"], 5);
        assert_eq!(v["negative_summary"]["modules_hit"], 1);
        assert_eq!(v["negative_summary"]["total_hits"], 2);
        assert_eq!(v["negative_summary"]["max_hits_per_module"], 2);

        // Enum and suffix rendering go through the CLI's display helpers.
        assert_eq!(v["chosen"]["grade"], "A");
        assert_eq!(v["chosen"]["suffix"], "_CALL");
        assert_eq!(v["chosen"]["scores"]["final_score"], 84);
        assert_eq!(v["string_anchor"], "@anchor");
    }

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(ExitKind::Success.code(), 0);
        assert_eq!(ExitKind::Internal.code(), 1);
        assert_eq!(ExitKind::SuccessWithWarnings.code(), 2);
        assert_eq!(ExitKind::Unresolved.code(), 3);
        assert_eq!(ExitKind::Ambiguous.code(), 4);
        assert_eq!(ExitKind::InvalidInput.code(), 5);
        assert_eq!(ExitKind::AccessDenied.code(), 6);
    }

    #[test]
    fn arch_mismatch_detects_definite_conflicts() {
        // requested x64 but the module is x86: actionable message naming the right bitness
        let msg = arch_mismatch(Arch::X64, Some(Arch::X86), "MapleStory.exe").unwrap();
        assert!(msg.contains("32-bit"), "{msg}");
        assert!(msg.contains("x86"));
        // matching architectures: no complaint
        assert!(arch_mismatch(Arch::X64, Some(Arch::X64), "m").is_none());
        // unknown actual architecture: cannot tell, so never block a scan on a guess
        assert!(arch_mismatch(Arch::X64, None, "m").is_none());
    }

    #[test]
    fn attach_permission_error_maps_to_access_denied() {
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(attach_err(denied).kind, ExitKind::AccessDenied);
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(attach_err(missing).kind, ExitKind::InvalidInput);
    }

    #[test]
    fn scan_exit_kind_ranks_ambiguous_over_unresolved_over_clean() {
        let clean = result_of(
            vec![mkrow("A", FindingStatus::FoundUnique, vec![0x10])],
            vec![],
            vec![],
        );
        assert_eq!(scan_exit_kind(&clean), ExitKind::Success);

        let unresolved = result_of(
            vec![mkrow("A", FindingStatus::NotFound, vec![])],
            vec![],
            vec!["A"],
        );
        assert_eq!(scan_exit_kind(&unresolved), ExitKind::Unresolved);

        let ambiguous = result_of(
            vec![mkrow(
                "A",
                FindingStatus::FoundAmbiguous { candidates: 2 },
                vec![0x10, 0x20],
            )],
            vec![],
            vec!["B"],
        );
        assert_eq!(scan_exit_kind(&ambiguous), ExitKind::Ambiguous);
    }

    #[test]
    fn scan_json_is_valid_and_marks_exportability() {
        let result = result_of(
            vec![
                mkrow("Uniq", FindingStatus::FoundUnique, vec![0x140]),
                mkrow(
                    "Amb",
                    FindingStatus::FoundAmbiguous { candidates: 2 },
                    vec![0x10, 0x20],
                ),
            ],
            vec![],
            vec![],
        );
        let stamp = BuildStamp {
            hash: 0xDEAD_BEEF,
            bytes: 2048,
            timestamp: 0,
            version: Some("1.0".to_string()),
        };
        let json = scan_json(&result, "MapleStory.exe", 0x1_4000_0000, &stamp);
        let v: serde_json::Value = serde_json::from_str(&json).expect("scan_json emits valid JSON");
        assert_eq!(v["module"], "MapleStory.exe");
        assert_eq!(v["ambiguous"], 1);
        assert_eq!(v["build_hash"], "00000000DEADBEEF");
        let findings = v["findings"].as_array().unwrap();
        let uniq = findings.iter().find(|f| f["name"] == "Uniq").unwrap();
        assert_eq!(uniq["exported"], true);
        let amb = findings.iter().find(|f| f["name"] == "Amb").unwrap();
        // an ambiguous row is reported but never exportable as an offset
        assert_eq!(amb["exported"], false);
        assert_eq!(amb["candidates"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn json_includes_ptr_target_fields() {
        let cand = SigCandidate {
            aob: "48 8D 05 ?? ?? ?? ??".to_string(),
            suffix: Suffix::Ptr,
            grade: Grade::A,
            score: 90,
            scores: SubScores {
                uniqueness: 90,
                stability: 80,
                entropy: 40,
                semantic: 82,
                resolver_confidence: 100,
                cross_build: 100,
                final_score: 90,
            },
            reasons: vec!["target validated as code".to_string()],
            bytes_len: 7,
            fixed: 3,
            wildcards: 4,
            fixed_ratio: 0.42,
            reloc_safe: true,
            gated: false,
            packed: false,
            per_version: vec![PerVersion {
                label: "a.exe".to_string(),
                match_rva: Some(0x20),
                resolved_target_rva: Some(0x1000),
                target_kind: Some(TargetKind::Code),
                fingerprint_similarity: Some(1.0),
                aob: None,
            }],
            diags: Vec::new(),
        };
        let report = SigReport {
            arch: Arch::X64,
            inputs: Vec::new(),
            unique_builds: 1,
            duplicate_groups: Vec::new(),
            chosen: Some(cand.clone()),
            alternates: vec![cand.clone()],
            rejected: vec![cand],
            shortlists: Vec::new(),
            aob_ranges: Vec::new(),
            diagnostics: Vec::new(),
        };
        let json = json_report(&report, &[], 0, &[], None);
        assert_eq!(
            json.matches("\"resolved_target_rva\": \"0x1000\"").count(),
            3
        );
        assert_eq!(json.matches("\"target_type\": \"code\"").count(), 3);
        // the JSON carries the scoring evidence: sub-scores, final_score, reasons, and the per-build
        // fingerprint similarity
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let chosen = &v["chosen"];
        assert_eq!(chosen["scores"]["resolver_confidence"], 100);
        assert_eq!(chosen["scores"]["final_score"], 90);
        assert!(!chosen["reasons"].as_array().unwrap().is_empty());
        assert_eq!(chosen["per_version"][0]["fingerprint_similarity"], 1.0);
        // the negative-corpus evidence is always present, even when nothing was scanned
        assert_eq!(v["negative_summary"]["modules_scanned"], 0);
        assert_eq!(v["negative_summary"]["modules_hit"], 0);
    }

    #[test]
    fn json_report_carries_negative_corpus_summary() {
        let report = SigReport {
            arch: Arch::X64,
            inputs: Vec::new(),
            unique_builds: 1,
            duplicate_groups: Vec::new(),
            chosen: None,
            alternates: Vec::new(),
            rejected: Vec::new(),
            shortlists: Vec::new(),
            aob_ranges: Vec::new(),
            diagnostics: Vec::new(),
        };
        let hits = [
            NegativeHit {
                label: "other.dll".into(),
                count: 2,
            },
            NegativeHit {
                label: "third.dll".into(),
                count: 1,
            },
        ];
        let json = json_report(&report, &hits, 5, &[], None);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["negative_summary"]["modules_scanned"], 5);
        assert_eq!(v["negative_summary"]["modules_hit"], 2);
        assert_eq!(v["negative_summary"]["total_hits"], 3);
        assert_eq!(v["negative_summary"]["max_hits_per_module"], 2);
    }

    #[test]
    fn cli_mksig_accepts_holdout_flag() {
        let cli = Cli::try_parse_from([
            "mapledumper",
            "mksig",
            "--client",
            "a.exe",
            "--sig",
            "48 8B",
            "--holdout",
        ])
        .unwrap();
        match cli.command {
            Command::Mksig(m) => assert!(m.holdout),
            _ => panic!("expected mksig"),
        }
    }

    #[test]
    fn cli_parses_scan_with_attach() {
        let cli =
            Cli::try_parse_from(["mapledumper", "scan", "--process", "x.exe", "--arch", "32"])
                .unwrap();
        match cli.command {
            Command::Scan(a) => {
                assert_eq!(a.attach.process.as_deref(), Some("x.exe"));
                assert_eq!(a.arch.as_deref(), Some("32"));
            }
            _ => panic!("expected scan"),
        }
    }

    #[test]
    fn cli_rejects_process_and_class_together() {
        let r = Cli::try_parse_from(["mapledumper", "scan", "--process", "x.exe", "--class", "W"]);
        assert!(r.is_err());
    }

    #[test]
    fn cli_requires_a_subcommand() {
        assert!(Cli::try_parse_from(["mapledumper"]).is_err());
    }

    #[test]
    fn cli_diff_takes_two_positionals() {
        let cli = Cli::try_parse_from(["mapledumper", "diff", "a.txt", "b.txt"]).unwrap();
        match cli.command {
            Command::Diff(a) => {
                assert_eq!(a.old, PathBuf::from("a.txt"));
                assert_eq!(a.new, PathBuf::from("b.txt"));
            }
            _ => panic!("expected diff"),
        }
    }

    #[test]
    fn cli_mksig_collects_repeated_clients() {
        let cli = Cli::try_parse_from([
            "mapledumper",
            "mksig",
            "--client",
            "a.exe",
            "--client",
            "b.exe",
            "--sig",
            "48 8B",
        ])
        .unwrap();
        match cli.command {
            Command::Mksig(m) => {
                assert_eq!(m.client.len(), 2);
                assert_eq!(m.sig.as_deref(), Some("48 8B"));
            }
            _ => panic!("expected mksig"),
        }
    }

    #[test]
    fn cli_mksig_collects_negatives() {
        let cli = Cli::try_parse_from([
            "mapledumper",
            "mksig",
            "--client",
            "a.exe",
            "--sig",
            "48 8B",
            "--negative",
            "other.dll",
            "--negative",
            "more.dll",
        ])
        .unwrap();
        match cli.command {
            Command::Mksig(m) => assert_eq!(m.negative.len(), 2),
            _ => panic!("expected mksig"),
        }
    }

    #[test]
    fn config_parses_known_keys() {
        let cfg = parse_config(
            "# a comment\nprocess = Maple.exe\narch = 32\nstrict = false\nout = dump\n",
            "test",
        )
        .unwrap();
        assert_eq!(cfg.process.as_deref(), Some("Maple.exe"));
        assert!(matches!(cfg.arch, Some(Arch::X86)));
        assert_eq!(cfg.strict, Some(false));
        assert_eq!(cfg.out, Some(PathBuf::from("dump")));
    }

    #[test]
    fn config_rejects_unknown_key() {
        assert!(parse_config("bogus = 1\n", "test").is_err());
    }

    #[test]
    fn cli_arch_overrides_config_but_config_fills_gaps() {
        let cfg = parse_config("arch = 32\n", "test").unwrap();
        assert!(matches!(resolve_arch(Some("64"), &cfg), Ok(Arch::X64)));
        assert!(matches!(resolve_arch(None, &cfg), Ok(Arch::X86)));
    }

    #[test]
    fn resolve_attach_prefers_cli_class_over_config_process() {
        let cfg = parse_config("process = Cfg.exe\n", "test").unwrap();
        let a = AttachArgs {
            process: None,
            class: Some("Win".to_string()),
            pid: None,
            module: None,
            no_wait: false,
            timeout: None,
        };
        let r = resolve_attach(&a, &cfg);
        assert_eq!(r.class.as_deref(), Some("Win"));
        assert!(r.process.is_none());
        assert_eq!(r.module, "MapleStory.exe");
    }

    #[test]
    fn resolve_attach_falls_back_to_config_process_and_module() {
        let cfg = parse_config("process = Cfg.exe\nmodule = Cfg.dll\n", "test").unwrap();
        let a = AttachArgs {
            process: None,
            class: None,
            pid: None,
            module: None,
            no_wait: true,
            timeout: None,
        };
        let r = resolve_attach(&a, &cfg);
        assert_eq!(r.process.as_deref(), Some("Cfg.exe"));
        assert_eq!(r.module, "Cfg.dll");
        assert!(!r.wait);
    }

    #[test]
    fn lenient_flag_overrides_config_strict() {
        let cfg = parse_config("strict = true\n", "test").unwrap();
        assert!(!resolve_strict(true, &cfg));
        assert!(resolve_strict(false, &cfg));
        assert!(resolve_strict(false, &Config::default()));
    }
}
