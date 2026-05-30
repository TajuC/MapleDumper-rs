use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use maple_core::output::{cheat_table, offsets_header, plain_text};
use maple_core::pattern::{Arch, ParseSeverity, parse_patterns_file, parse_patterns_file_strict};
use maple_core::{
    AttachOptions, BuildStamp, DiffReport, FindingStatus, Locator, Pattern, ProfileReport,
    ScanResult, Target, apply_string_anchors, assembly_scan, diff, lint, parse_asm_patterns,
    parse_dump, parse_stamp, profile, scan,
};
use maple_core::{
    FileImage, HoldoutResult, ImageInput, NegativeHit, SigCandidate, SigOptions, SigReport,
    TargetKind, TargetSpec, generate, holdout_validate, negative_corpus_hits,
};

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
    match s.trim().to_ascii_lowercase().as_str() {
        "64" | "x64" | "amd64" | "x86_64" | "x86-64" => Ok(Arch::X64),
        "32" | "x86" | "i386" | "x86_32" => Ok(Arch::X86),
        other => Err(format!("invalid arch '{other}' (use 32 or 64)")),
    }
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

fn require_patterns(path: &Path, arch: Arch, strict: bool) -> Result<Vec<Pattern>, String> {
    let patterns = load_patterns(path, arch, strict)?;
    if patterns.is_empty() {
        return Err(format!("no patterns loaded from {}", path.display()));
    }
    println!("[+] loaded {} patterns", patterns.len());
    Ok(patterns)
}

fn attach_target(at: &ResolvedAttach, cancel: &AtomicBool) -> Result<Target, String> {
    let opts = AttachOptions {
        wait: at.wait,
        timeout: at.timeout,
        poll: Duration::from_millis(300),
    };
    let target = if let Some(pid) = at.pid {
        println!("[+] attaching to pid {pid}");
        Target::attach_pid(pid, &at.module).map_err(|e| format!("attach failed: {e}"))?
    } else {
        let loc = locator(at)?;
        if let Locator::Name(name) = &loc {
            let candidates = maple_core::process::process_candidates(name);
            if candidates.len() > 1 {
                println!("[!] {} processes match '{name}':", candidates.len());
                for c in &candidates {
                    println!(
                        "      pid {}  {}",
                        c.pid,
                        c.path.as_deref().unwrap_or("(path unavailable)")
                    );
                }
                println!("    attaching to the first; pass --pid <pid> to choose another");
            }
        }
        if at.wait {
            let what = match &loc {
                Locator::Name(name) => format!("process {name}"),
                Locator::Class(class) => format!("window class {class}"),
            };
            println!("[*] waiting for {what} (Ctrl-C to cancel)...");
        }
        Target::attach(&loc, &at.module, &opts, cancel)
            .map_err(|e| format!("attach failed: {e}"))?
    };
    println!(
        "[+] attached; module {} base 0x{:X} size 0x{:X}",
        at.module, target.module.base, target.module.size
    );
    Ok(target)
}

fn write_outputs(
    out: &Path,
    ce: bool,
    offsets: bool,
    result: &ScanResult,
    module: &str,
    base: u64,
    stamp: Option<&BuildStamp>,
) -> Result<(), String> {
    std::fs::create_dir_all(out).map_err(|e| format!("create {}: {e}", out.display()))?;

    let header = stamp.map(BuildStamp::header_line);
    let update = out.join("update.txt");
    let contents = if ce {
        cheat_table(&result.findings, module)
    } else {
        plain_text(&result.findings, module, base, header.as_deref())
    };
    std::fs::write(&update, contents).map_err(|e| format!("write {}: {e}", update.display()))?;
    println!("[+] wrote {}", update.display());

    if offsets {
        let header = out.join("offsets.h");
        std::fs::write(&header, offsets_header(&result.findings, module, base))
            .map_err(|e| format!("write {}: {e}", header.display()))?;
        println!("[+] wrote {}", header.display());
    }
    Ok(())
}

fn cmd_scan(a: ScanArgs, cfg: &Config) -> Result<(), String> {
    let arch = resolve_arch(a.arch.as_deref(), cfg)?;
    let patterns_path = resolve_patterns(a.patterns.as_ref(), cfg);
    let out = a
        .out
        .clone()
        .or_else(|| cfg.out.clone())
        .unwrap_or_else(|| PathBuf::from("."));
    let strict = resolve_strict(a.lenient, cfg);
    let patterns = require_patterns(&patterns_path, arch, strict)?;

    let at = resolve_attach(&a.attach, cfg);
    let cancel = AtomicBool::new(false);
    let target = attach_target(&at, &cancel)?;

    let regions = target.regions();
    println!("[+] scanning {} regions", regions.len());
    let mut result = scan(
        &target,
        target.module.base,
        target.module.size,
        &regions,
        &patterns,
        arch,
    );

    if patterns.iter().any(|p| p.string_anchor.is_some()) {
        let img = ImageInput {
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
        apply_string_anchors(&mut result, &img, &patterns);
    }

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
    println!("[+] total matches {}", result.total_matches);

    let mut stamp = BuildStamp::capture(&target, target.module.base, &target.code_regions());
    stamp.version = target.file_version();
    println!("[+] build {} ({} bytes)", stamp.short(), stamp.bytes);

    write_outputs(
        &out,
        a.ce,
        !a.no_offsets,
        &result,
        &at.module,
        target.module.base as u64,
        Some(&stamp),
    )
}

fn cmd_lint(a: LintArgs, cfg: &Config) -> Result<(), String> {
    let arch = resolve_arch(a.arch.as_deref(), cfg)?;
    let patterns_path = resolve_patterns(a.patterns.as_ref(), cfg);
    let strict = resolve_strict(a.lenient, cfg);
    let patterns = require_patterns(&patterns_path, arch, strict)?;
    print_lints(&patterns);
    Ok(())
}

fn cmd_diff(a: DiffArgs) -> Result<(), String> {
    let old_text =
        std::fs::read_to_string(&a.old).map_err(|e| format!("read {}: {e}", a.old.display()))?;
    let new_text =
        std::fs::read_to_string(&a.new).map_err(|e| format!("read {}: {e}", a.new.display()))?;
    print_build_compare(
        parse_stamp(&old_text).as_ref(),
        parse_stamp(&new_text).as_ref(),
    );
    print_diff(&diff(&parse_dump(&old_text), &parse_dump(&new_text)));
    Ok(())
}

fn cmd_asm(a: AsmArgs, cfg: &Config) -> Result<(), String> {
    let arch = resolve_arch(a.arch.as_deref(), cfg)?;
    let at = resolve_attach(&a.attach, cfg);
    let cancel = AtomicBool::new(false);
    let target = attach_target(&at, &cancel)?;

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
    Ok(())
}

fn cmd_profile(a: ProfileArgs, cfg: &Config) -> Result<(), String> {
    let arch = resolve_arch(a.arch.as_deref(), cfg)?;
    let patterns_path = resolve_patterns(a.patterns.as_ref(), cfg);
    let strict = resolve_strict(a.lenient, cfg);
    let patterns = require_patterns(&patterns_path, arch, strict)?;

    let at = resolve_attach(&a.attach, cfg);
    let cancel = AtomicBool::new(false);
    let target = attach_target(&at, &cancel)?;

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
    Ok(())
}

fn run() -> Result<(), String> {
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
        "  serial  (1 thread)   : {:>6} ms  ({:.2} GB/s)",
        r.scan_serial_ms,
        gbps(r.bytes, r.scan_serial_ms)
    );
    println!(
        "  parallel ({:>2} cores)  : {:>6} ms  ({:.2} GB/s)",
        r.cores,
        r.scan_parallel_ms,
        gbps(r.bytes, r.scan_parallel_ms)
    );
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
        "verdict: read(1) {read1} ms | scan(parallel) {} ms | resolve {} ms | full {} ms",
        r.scan_parallel_ms, r.resolve_ms, r.full_ms
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

fn print_lints(patterns: &[Pattern]) {
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
}
#[derive(Serialize)]
struct JCand {
    aob: String,
    suffix: String,
    grade: String,
    score: u32,
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
struct JHold {
    held_out: String,
    generated: bool,
    matched: bool,
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
    holdout: Vec<JHold>,
    diagnostics: Vec<String>,
}

fn jcand(c: &SigCandidate) -> JCand {
    JCand {
        aob: c.aob.clone(),
        suffix: c.suffix.as_str().to_string(),
        grade: c.grade.letter().to_string(),
        score: c.score,
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
            })
            .collect(),
        diags: c.diags.iter().map(|d| d.to_string()).collect(),
    }
}

fn json_report(r: &SigReport, negatives: &[NegativeHit], holdout: &[HoldoutResult]) -> String {
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
        holdout: holdout
            .iter()
            .map(|h| JHold {
                held_out: h.held_out.clone(),
                generated: h.generated,
                matched: h.matched_holdout,
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
        "      score {}, {} bytes, {} fixed, {} wild, ratio {:.2}, reloc_safe {}",
        c.score, c.bytes_len, c.fixed, c.wildcards, c.fixed_ratio, c.reloc_safe
    );
    for p in &c.per_version {
        let m = p
            .match_rva
            .map_or_else(|| "-".to_string(), |v| format!("0x{v:X}"));
        let t = p
            .resolved_target_rva
            .map_or_else(String::new, |v| format!(" -> 0x{v:X}"));
        println!("        {} @ {m}{t}", p.label);
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

fn cmd_mksig(m: MksigArgs) -> Result<(), String> {
    let clients = collect_clients(&m.client, m.client_dir.as_deref(), m.ref_path.as_deref())?;
    let has_sig = m.sig.is_some();
    let has_ref = m.ref_path.is_some() || m.rva.is_some();
    if has_sig == has_ref {
        return Err("provide exactly one of --sig OR (--ref + --rva)".to_string());
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

    let report = generate(&inputs, &spec, &opts);

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

    if m.json || m.json_out.is_some() {
        let json = json_report(&report, &neg_hits, &holdout);
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
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[error] {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maple_core::{Grade, PerVersion, Suffix};

    #[test]
    fn json_includes_ptr_target_fields() {
        let cand = SigCandidate {
            aob: "48 8D 05 ?? ?? ?? ??".to_string(),
            suffix: Suffix::Ptr,
            grade: Grade::A,
            score: 90,
            bytes_len: 7,
            fixed: 3,
            wildcards: 4,
            fixed_ratio: 0.42,
            reloc_safe: true,
            per_version: vec![PerVersion {
                label: "a.exe".to_string(),
                match_rva: Some(0x20),
                resolved_target_rva: Some(0x1000),
                target_kind: Some(TargetKind::Code),
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
            diagnostics: Vec::new(),
        };
        let json = json_report(&report, &[], &[]);
        assert_eq!(
            json.matches("\"resolved_target_rva\": \"0x1000\"").count(),
            3
        );
        assert_eq!(json.matches("\"target_type\": \"code\"").count(), 3);
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
